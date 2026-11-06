//! Tests of the probes module: the catalog against §17, every expectation of the table,
//! each §8.1 and VM-W09 rule from both sides, guest reports from a real host link, the
//! CORE-01 coverage map and adapters, the VM-CP-05 bridge and the boundary report.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;

use super::catalog::{
    catalog, check, CheckId, CorroboratingFact, Part, RunProfile, Side, SourceKind,
};
use super::confinement::{status_of_verdict, Vm05Evaluation};
use super::core01::{
    hypervisor_of, BootedImageMatchesManifestProbe, CloneIdentityResetProbe,
    CredentialAbsentFromScannedLocationsProbe, DestinationPolicyEnforcedProbe,
    DeviceAssignmentIsolatedProbe, HypervisorAvailableProbe, HypervisorConfigurationMatchesProbe,
    HypervisorConfinedProbe, NoGuestNetworkDeviceProbe, PerimeterRuleProbe,
};
use super::coverage::{checks_for, core01_coverage, coverage_of, Core01Coverage};
use super::expect::{
    expectation, expectations, Expect, ExpectationId, HostScope, ObservationError, Observed,
    ObservedKind, Role,
};
use super::fakes::*;
use super::outcome::{
    Evidence, HostKind, IgnoredClaim, NotTestedReason, Observations, OutcomeError, ProbeOutcome,
    RunResult, RunnerInconclusive, TestTier,
};
use super::report::{Applicability, BoundaryReport, CheckInput, GpuPath, HostProfile, ReportError};
use super::rules::{judge, CheckRefusal, CheckStatus, Failure, InconclusiveReason, JudgeContext};
use crate::foundation::evidence::{
    Backend, BackendRelease, Capability, CredentialScanSubject, CudaAllocationSubject,
    EvidenceRefusal, GpuDeviceSubject, GpuPairSubject, HostSubject, HypervisorKind,
    HypervisorProcessSubject, HypervisorSubject, ModelCheckpointSubject, ObservationResult,
    OperatingSystemSubject, OsKind, PerimeterRuleSubject, ProbeAdapter, ProbeRegistry,
    ProviderKind, ProviderSubject, RegistryError, Requirement, RuntimeSubject, SandboxBootSubject,
    SnapshotClonesSubject, SourceClass, Staleness, Subject, SubjectKind, SupportDetail,
    TransportBrokerSubject, UnknownReason, UnsupportedReason,
};
use crate::foundation::ids::{digest, ExecutionCategory, ManualClock};
use crate::sandbox::backend::{
    Architecture, BackendKind, BuildId, Facet, HostBuild, ObservationProblem,
};
use crate::sandbox::link::{AllProbesPassed, LinkMessage, ProbeOutcome as GuestVerdict};
use crate::sandbox_contract::confinement::{
    Check as ConfinementCheck, CheckOutcome, CheckVerdict, ConfinementVerdict, FailureReason,
    InconclusiveReason as ConfinementInconclusive, VerdictMeaning, VerdictOutcome, WorkloadProfile,
};

const OSES: [OsKind; 3] = [OsKind::Linux, OsKind::Windows, OsKind::MacOs];

// ---------------------------------------------------------------- helpers

/// An observation that meets `expect`.
fn meeting(expect: Expect) -> Observed {
    match expect {
        Expect::Refused => refused(),
        Expect::Succeeds => succeeded(),
        Expect::Absent => absent(),
        Expect::Present => present(),
        Expect::Happens => happened(),
        Expect::NeverHappens => Observed::Event { happened: false },
        Expect::OneOf(allowed) => value(allowed[0]),
        Expect::WithinLimit => Observed::Bounded { value: 1, limit: 2 },
        Expect::Matches => matching("reference"),
        Expect::AllDistinct => distinct(2),
    }
}

/// An observation of the right kind that does not meet `expect`.
fn violating(expect: Expect) -> Observed {
    match expect {
        Expect::Refused => succeeded(),
        Expect::Succeeds => refused(),
        Expect::Absent => present(),
        Expect::Present => absent(),
        Expect::Happens => Observed::Event { happened: false },
        Expect::NeverHappens => happened(),
        Expect::OneOf(_) => value("tcg"),
        Expect::WithinLimit => Observed::Bounded { value: 3, limit: 2 },
        Expect::Matches => differing("reference"),
        Expect::AllDistinct => {
            let same = digest("yougori/test/probes/identity/v1", &[b"same"]);
            Observed::Identities {
                values: vec![same, same],
            }
        }
    }
}

/// Observations of `part` of `check` that meet every applicable expectation on `os`,
/// the positive control included.
fn passing(check_number: u8, part: Part, os: OsKind) -> Observations {
    expectations()
        .iter()
        .filter(|entry| {
            entry.check == check_id(check_number) && entry.part == part && entry.scope.applies(os)
        })
        .map(|entry| (entry.id, meeting(entry.expect)))
        .collect()
}

/// The host-grade kind a check's part accepts.
fn kind_for(check_number: u8) -> HostKind {
    match check(check_id(check_number)).side {
        Side::ControlledExternal => HostKind::ControlledExternal,
        _ => HostKind::Host,
    }
}

fn host(
    registry: &ProbeRegistry<Arc<ManualClock>>,
    check_number: u8,
    part: Part,
    kind: HostKind,
    observations: Observations,
) -> ProbeOutcome {
    ProbeOutcome::host(
        check_id(check_number),
        part,
        kind,
        registry.now(),
        FRESH,
        configuration("host-a"),
        RunResult::Observed { observations },
    )
    .unwrap()
}

/// Host-grade outcomes for every part of `check`, all passing on `os`.
fn all_passing(
    registry: &ProbeRegistry<Arc<ManualClock>>,
    check_number: u8,
    os: OsKind,
) -> Vec<ProbeOutcome> {
    check(check_id(check_number))
        .parts()
        .into_iter()
        .map(|part| {
            host(
                registry,
                check_number,
                part,
                kind_for(check_number),
                passing(check_number, part, os),
            )
        })
        .collect()
}

fn guest_outcome(
    registry: &ProbeRegistry<Arc<ManualClock>>,
    check_number: u8,
    part: Part,
    reports: &[crate::sandbox::link::GuestReport],
) -> Result<ProbeOutcome, OutcomeError> {
    ProbeOutcome::guest(
        check_id(check_number),
        part,
        reports,
        vm(),
        boot(),
        registry.now(),
        FRESH,
        configuration("host-a"),
    )
}

fn linux_context(registry: &ProbeRegistry<Arc<ManualClock>>) -> JudgeContext {
    context(registry, configuration("host-a"), OsKind::Linux)
}

fn hypervisor_subject(hypervisor: HypervisorKind) -> Subject {
    Subject::Hypervisor(HypervisorSubject {
        machine: digest("yougori/test/probes/machine/v1", &[b"machine"]),
        hypervisor,
    })
}

fn perimeter_subject() -> Subject {
    let part = |name: &[u8]| digest("yougori/test/probes/perimeter/v1", &[name]);
    Subject::PerimeterRule(PerimeterRuleSubject {
        machine: part(b"machine"),
        perimeter: part(b"perimeter"),
        rule: part(b"block-private"),
        principal: part(b"broker"),
    })
}

fn linux_profile(profiles: &[RunProfile]) -> HostProfile {
    HostProfile {
        host: HostBuild {
            os: OsKind::Linux,
            build: BuildId::new("6.8.0-45").unwrap(),
            architecture: Architecture::X86_64,
        },
        backend: BackendKind::Firecracker,
        profiles: profiles.iter().copied().collect(),
    }
}

// ---------------------------------------------------------------- catalog and table

#[test]
fn the_catalog_has_every_section_17_row_once_in_order() {
    let ids: Vec<u8> = catalog().iter().map(|row| row.id.number()).collect();
    assert_eq!(ids, (1..=35).collect::<Vec<u8>>());
    assert_eq!(CheckId::new(0), None);
    assert_eq!(CheckId::new(36), None);
    for id in CheckId::all() {
        assert_eq!(check(id).id, id);
    }
    // Spot checks of the "Families" column (lines 3151–3185).
    let families = |number: u8| -> Vec<u8> {
        check(check_id(number))
            .families
            .iter()
            .map(|family| family.number())
            .collect()
    };
    assert_eq!(families(1), [1, 42]);
    assert_eq!(families(11), [11, 26, 27]);
    assert_eq!(families(14), [14, 24]);
    assert_eq!(families(24), [25, 46]);
    assert_eq!(families(25), [28, 29]);
    assert_eq!(families(35), [47, 50]);
    // Every VM-P family from 1 to 50 is served by at least one check.
    let served: BTreeSet<u8> = catalog()
        .iter()
        .flat_map(|row| row.families.iter().map(|family| family.number()))
        .collect();
    assert_eq!(served, (1..=50).collect::<BTreeSet<u8>>());
    assert_eq!(check_id(1).to_string(), "VM-CP-01");
}

#[test]
fn every_check_has_typed_expectations_and_its_control_and_corroboration_exist() {
    let mut names = BTreeSet::new();
    for entry in expectations() {
        assert!(names.insert(entry.id.as_str()), "{} twice", entry.id);
        assert_eq!(ExpectationId::named(entry.id.as_str()), Some(entry.id));
        assert!(entry
            .id
            .as_str()
            .starts_with(&format!("cp{:02}.", entry.check.number())));
        assert!(
            check(entry.check).parts().contains(&entry.part),
            "{}",
            entry.id
        );
        assert!(!entry.says.is_empty());
    }
    assert_eq!(ExpectationId::named("cp99.nothing"), None);
    for row in catalog() {
        for os in OSES {
            if row.runs_on(os) {
                assert!(
                    row.observations_for(Part::Primary, os).next().is_some(),
                    "{} has no observation on {os}",
                    row.id
                );
            }
        }
        if let Some(control) = row.control() {
            assert_eq!(control.check, row.id);
            assert_eq!(control.role, Role::PositiveControl);
            assert!(row.parts().contains(&control.part));
        }
        for fact in row.side.corroboration() {
            let part = Part::Corroboration { fact: *fact };
            assert!(
                row.observations_for(part, OsKind::Linux).next().is_some(),
                "{} lacks an observation for {fact}",
                row.id
            );
        }
    }
    // Host-specific rows give each host operating system its own observations.
    for number in [4, 33] {
        let row = check(check_id(number));
        assert!(row.host_specific);
        for os in OSES {
            assert!(row.runs_on(os), "{} on {os}", row.id);
        }
        assert!(!row.runs_on(OsKind::Wsl2));
    }
    // Guest-reported rows name their host corroboration (lines 3155, 3159, 3171).
    let corroboration = |number: u8| check(check_id(number)).side.corroboration().to_vec();
    assert_eq!(
        corroboration(5),
        [
            CorroboratingFact::BootedRootImage,
            CorroboratingFact::KernelBuildRecord
        ]
    );
    assert_eq!(corroboration(9), [CorroboratingFact::NoGuestNetworkDevice]);
    assert_eq!(
        corroboration(21),
        [
            CorroboratingFact::CloneIdentities,
            CorroboratingFact::PreSnapshotApprovalRefused
        ]
    );
    for row in catalog() {
        let guest = matches!(row.side, Side::GuestReportedWithHostCorroboration { .. });
        assert_eq!(!guest, row.side.is_host_only(), "{}", row.id);
    }
}

#[test]
fn every_predicate_judges_its_own_kind_only() {
    let samples = [
        refused(),
        present(),
        happened(),
        value("kvm"),
        Observed::Bounded { value: 1, limit: 1 },
        matching("x"),
        distinct(3),
    ];
    let predicates = [
        Expect::Refused,
        Expect::Succeeds,
        Expect::Absent,
        Expect::Present,
        Expect::Happens,
        Expect::NeverHappens,
        Expect::OneOf(&["kvm"]),
        Expect::WithinLimit,
        Expect::Matches,
        Expect::AllDistinct,
    ];
    for expect in predicates {
        assert_eq!(expect.holds(&meeting(expect)), Ok(true), "{expect:?}");
        assert_eq!(expect.holds(&violating(expect)), Ok(false), "{expect:?}");
        for sample in &samples {
            if sample.kind() != expect.judges() {
                assert_eq!(
                    expect.holds(sample),
                    Err(ObservationError::WrongKind {
                        expected: expect.judges(),
                        found: sample.kind(),
                    })
                );
            }
        }
    }
    // A limit is inclusive; one identity cannot show two clones are distinct.
    assert_eq!(
        Expect::WithinLimit.holds(&Observed::Bounded { value: 2, limit: 2 }),
        Ok(true)
    );
    assert_eq!(
        Expect::AllDistinct.holds(&distinct(1)),
        Err(ObservationError::TooFewIdentities { found: 1 })
    );
    assert_eq!(Expect::OneOf(&["kvm"]).judges(), ObservedKind::Value);
}

#[test]
fn every_check_passes_with_observations_that_meet_its_expectations_on_each_host() {
    let (registry, _clock) = registry();
    for os in OSES {
        let context = context(&registry, configuration("host-a"), os);
        for row in catalog() {
            let outcomes = all_passing(&registry, row.id.number(), os);
            // A check the host cannot run (VM-CP-31 off Linux) reads not tested.
            let expected = if row.runs_on(os) {
                CheckStatus::Passed
            } else {
                CheckStatus::NotTested {
                    reason: NotTestedReason::NoObservationForHost { os },
                }
            };
            assert_eq!(
                judge(row, &outcomes, &context),
                expected,
                "{} on {os}",
                row.id
            );
        }
    }
}

#[test]
fn vm_cp_31_runs_on_linux_hosts_only_and_reads_not_tested_elsewhere() {
    let (registry, _clock) = registry();
    let row = check(check_id(31));
    assert!(row.host_specific);
    assert!(row.runs_on(OsKind::Linux));
    for os in [OsKind::Windows, OsKind::MacOs, OsKind::Wsl2] {
        assert!(!row.runs_on(os), "{os}");
        assert_eq!(row.observations_for(Part::Primary, os).count(), 0, "{os}");
        // Even Linux observations that all hold do not make it run there.
        assert_eq!(
            judge(
                row,
                &all_passing(&registry, 31, OsKind::Linux),
                &context_for_os(&registry, os)
            ),
            CheckStatus::NotTested {
                reason: NotTestedReason::NoObservationForHost { os }
            },
            "{os}"
        );
    }
    for name in [
        "cp31.incomplete-iommu-group",
        "cp31.display-owning-gpu",
        "cp31.reset-capability-checked",
        "cp31.acs-state-checked",
    ] {
        assert_eq!(
            expectation(id(name)).unwrap().scope,
            HostScope::Only(OsKind::Linux),
            "{name}"
        );
    }
    assert_eq!(row.control().unwrap().scope, HostScope::AnyHost);
    assert_eq!(
        judge(
            row,
            &all_passing(&registry, 31, OsKind::Linux),
            &linux_context(&registry)
        ),
        CheckStatus::Passed
    );

    // A GPU VM profile on a Windows host: the GPU path is explained as Linux only.
    let windows = HostProfile {
        host: HostBuild {
            os: OsKind::Windows,
            build: BuildId::new("26100.1").unwrap(),
            architecture: Architecture::X86_64,
        },
        backend: BackendKind::Qemu,
        profiles: BTreeSet::from([RunProfile::Strict, RunProfile::GpuVm]),
    };
    let mut inputs = BTreeMap::new();
    inputs.insert(
        check_id(31),
        CheckInput::Outcomes(all_passing(&registry, 31, OsKind::Linux)),
    );
    let report =
        BoundaryReport::assemble(windows, inputs, &context_for_os(&registry, OsKind::Windows))
            .unwrap();
    match report.gpu() {
        GpuPath::Unavailable { status, why } => {
            assert_eq!(
                status,
                &CheckStatus::NotTested {
                    reason: NotTestedReason::NoObservationForHost {
                        os: OsKind::Windows
                    }
                }
            );
            assert!(why.contains("Linux hosts only"), "{why}");
            assert!(why.contains("Windows host"), "{why}");
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn any_single_observation_that_does_not_hold_fails_exactly_that_expectation() {
    let (registry, _clock) = registry();
    let context = linux_context(&registry);
    for entry in expectations()
        .iter()
        .filter(|entry| entry.role == Role::Observation && entry.scope.applies(OsKind::Linux))
    {
        let number = entry.check.number();
        let outcomes: Vec<ProbeOutcome> = check(entry.check)
            .parts()
            .into_iter()
            .map(|part| {
                let mut observations = passing(number, part, OsKind::Linux);
                if part == entry.part {
                    observations.insert(entry.id, violating(entry.expect));
                }
                host(&registry, number, part, kind_for(number), observations)
            })
            .collect();
        assert_eq!(
            judge(check(entry.check), &outcomes, &context),
            CheckStatus::Failed {
                failure: Failure::Expectation {
                    id: entry.id,
                    part: entry.part
                }
            },
            "{}",
            entry.id
        );
    }
}

// ---------------------------------------------------------------- rules

#[test]
fn a_failed_or_missing_positive_control_makes_any_result_inconclusive() {
    let (registry, _clock) = registry();
    let context = linux_context(&registry);
    for row in catalog().iter().filter(|row| row.control().is_some()) {
        let control = row.control().unwrap();
        let number = row.id.number();
        for (control_value, expected) in [
            (
                Some(violating(control.expect)),
                InconclusiveReason::ControlFailed { id: control.id },
            ),
            (
                None,
                InconclusiveReason::NoPositiveControl { id: control.id },
            ),
        ] {
            let outcomes: Vec<ProbeOutcome> = row
                .parts()
                .into_iter()
                .map(|part| {
                    let mut observations = passing(number, part, OsKind::Linux);
                    if part == control.part {
                        observations.remove(&control.id);
                        if let Some(seen) = &control_value {
                            observations.insert(control.id, seen.clone());
                        }
                    }
                    host(&registry, number, part, kind_for(number), observations)
                })
                .collect();
            assert_eq!(
                judge(row, &outcomes, &context),
                CheckStatus::Inconclusive {
                    reason: expected.clone()
                },
                "{}",
                row.id
            );
        }
    }
    // VM-CP-06: the forbidden connection was refused, but the listener was not reachable
    // from an unconfined process either, so the refusal is not attributable to policy.
    let mut observations = passing(6, Part::Primary, OsKind::Linux);
    observations.insert(
        id("cp06.forbidden-listener-reachable-unconfined"),
        refused(),
    );
    let outcome = host(
        &registry,
        6,
        Part::Primary,
        HostKind::ControlledExternal,
        observations,
    );
    assert!(matches!(
        judge(check(check_id(6)), &[outcome], &context),
        CheckStatus::Inconclusive {
            reason: InconclusiveReason::ControlFailed { .. }
        }
    ));
}

#[test]
fn inconclusive_and_missing_observations_never_pass() {
    let (registry, _clock) = registry();
    let context = linux_context(&registry);
    let row = check(check_id(8));
    // The runner timed out: a timeout is never a refusal.
    let timed_out = ProbeOutcome::host(
        row.id,
        Part::Primary,
        HostKind::Host,
        registry.now(),
        FRESH,
        configuration("host-a"),
        RunResult::Inconclusive {
            reason: RunnerInconclusive::TimedOut,
        },
    )
    .unwrap();
    assert_eq!(
        judge(row, &[timed_out], &context),
        CheckStatus::Inconclusive {
            reason: InconclusiveReason::Runner {
                part: Part::Primary,
                reason: RunnerInconclusive::TimedOut
            }
        }
    );
    // One observation missing.
    let mut observations = passing(8, Part::Primary, OsKind::Linux);
    observations.remove(&id("cp08.metadata-address"));
    assert_eq!(
        judge(
            row,
            &[host(
                &registry,
                8,
                Part::Primary,
                HostKind::Host,
                observations
            )],
            &context
        ),
        CheckStatus::Inconclusive {
            reason: InconclusiveReason::MissingObservation {
                id: id("cp08.metadata-address")
            }
        }
    );
    // One observation of the wrong kind.
    let mut observations = passing(8, Part::Primary, OsKind::Linux);
    observations.insert(id("cp08.broadcast"), present());
    assert!(matches!(
        judge(
            row,
            &[host(
                &registry,
                8,
                Part::Primary,
                HostKind::Host,
                observations
            )],
            &context
        ),
        CheckStatus::Inconclusive {
            reason: InconclusiveReason::InconsistentObservation { .. }
        }
    ));
    // A conclusive failure is reported even when another observation is missing.
    let mut observations = passing(8, Part::Primary, OsKind::Linux);
    observations.remove(&id("cp08.metadata-address"));
    observations.insert(id("cp08.multicast"), succeeded());
    assert!(matches!(
        judge(
            row,
            &[host(
                &registry,
                8,
                Part::Primary,
                HostKind::Host,
                observations
            )],
            &context
        ),
        CheckStatus::Failed { .. }
    ));
}

#[test]
fn not_tested_is_never_a_pass() {
    let (registry, _clock) = registry();
    let context = linux_context(&registry);
    let row = check(check_id(31));
    assert_eq!(
        judge(row, &[], &context),
        CheckStatus::NotTested {
            reason: NotTestedReason::NotRun
        }
    );
    let unavailable =
        ProbeOutcome::not_tested(row.id, Part::Primary, NotTestedReason::UnavailableHardware)
            .unwrap();
    let status = judge(row, &[unavailable], &context);
    assert_eq!(
        status,
        CheckStatus::NotTested {
            reason: NotTestedReason::UnavailableHardware
        }
    );
    assert!(!status.passed());
    assert!(status.to_string().starts_with("not tested"));
    let tier = ProbeOutcome::not_tested(
        check_id(24),
        Part::Primary,
        NotTestedReason::NeedsTier {
            tier: TestTier::DisposableVm,
        },
    )
    .unwrap();
    assert!(!judge(check(check_id(24)), &[tier], &context).passed());
    // A host-specific check with nothing for a WSL2 host.
    let wsl = context_for_os(&registry, OsKind::Wsl2);
    assert_eq!(
        judge(
            check(check_id(4)),
            &all_passing(&registry, 4, OsKind::Linux),
            &wsl
        ),
        CheckStatus::NotTested {
            reason: NotTestedReason::NoObservationForHost { os: OsKind::Wsl2 }
        }
    );
}

fn context_for_os(registry: &ProbeRegistry<Arc<ManualClock>>, os: OsKind) -> JudgeContext {
    context(registry, configuration("host-a"), os)
}

#[test]
fn a_host_specific_check_judges_the_hosts_own_observations() {
    let (registry, _clock) = registry();
    let row = check(check_id(4));
    // Linux observations judged on a Windows host: the Windows ones are missing.
    let linux_only = all_passing(&registry, 4, OsKind::Linux);
    assert_eq!(
        judge(
            row,
            &linux_only,
            &context_for_os(&registry, OsKind::Windows)
        ),
        CheckStatus::Inconclusive {
            reason: InconclusiveReason::MissingObservation {
                id: id("cp04.windows.restricted-low-integrity-token")
            }
        }
    );
    // The descriptor count is judged against the profile's number (line 3154).
    let mut observations = passing(4, Part::Primary, OsKind::Linux);
    observations.insert(
        id("cp04.linux.descriptors"),
        Observed::Bounded {
            value: 65,
            limit: 64,
        },
    );
    assert!(matches!(
        judge(
            row,
            &[host(
                &registry,
                4,
                Part::Primary,
                HostKind::Host,
                observations
            )],
            &context_for_os(&registry, OsKind::Linux)
        ),
        CheckStatus::Failed { .. }
    ));
}

#[test]
fn stale_reconfigured_or_other_clock_outcomes_are_refused() {
    let (registry, clock) = registry();
    let outcomes = all_passing(&registry, 13, OsKind::Linux);
    let row = check(check_id(13));
    // Older than the reader's maximum age (300 s; the outcome itself stays fresh 600 s).
    clock.advance(MAX_AGE + Duration::from_secs(1));
    match judge(row, &outcomes, &linux_context(&registry)) {
        CheckStatus::Refused {
            refusal:
                CheckRefusal::NotCurrent {
                    problem:
                        ObservationProblem::Stale {
                            staleness: Staleness::TooOld { age, limit },
                        },
                    ..
                },
        } => {
            assert_eq!(limit, MAX_AGE);
            assert!(age > limit);
        }
        other => panic!("{other:?}"),
    }
    // Under another configuration.
    let (registry, _clock) = super::fakes::registry();
    let outcomes = all_passing(&registry, 13, OsKind::Linux);
    let reconfigured = context(&registry, configuration("host-b"), OsKind::Linux);
    assert!(matches!(
        judge(row, &outcomes, &reconfigured),
        CheckStatus::Refused {
            refusal: CheckRefusal::NotCurrent {
                problem: ObservationProblem::OtherConfiguration { .. },
                ..
            }
        }
    ));
    // Judged on another registry's clock, as after a restart.
    let (other, _clock) = super::fakes::registry();
    assert!(matches!(
        judge(row, &outcomes, &linux_context(&other)),
        CheckStatus::Refused {
            refusal: CheckRefusal::NotCurrent {
                problem: ObservationProblem::Stale {
                    staleness: Staleness::OtherClock
                },
                ..
            }
        }
    ));
}

#[test]
fn a_controlled_external_check_needs_a_controlled_external_observation() {
    let (registry, _clock) = registry();
    let outcome = host(
        &registry,
        6,
        Part::Primary,
        HostKind::Host,
        passing(6, Part::Primary, OsKind::Linux),
    );
    assert_eq!(
        judge(check(check_id(6)), &[outcome], &linux_context(&registry)),
        CheckStatus::Refused {
            refusal: CheckRefusal::WrongSource {
                part: Part::Primary,
                required: SourceKind::ControlledExternal,
                found: SourceKind::Host
            }
        }
    );
    // A controlled external observation is host-grade and may stand for a host one.
    assert!(SourceKind::ControlledExternal.may_stand_for(SourceKind::Host));
    assert!(!SourceKind::Guest.may_stand_for(SourceKind::Host));
    assert_eq!(
        SourceKind::ControlledExternal.source_class(),
        SourceClass::HostProbe
    );
}

#[test]
fn outcomes_of_another_check_or_twice_for_one_part_are_refused() {
    let (registry, _clock) = registry();
    let context = linux_context(&registry);
    let mut outcomes = all_passing(&registry, 13, OsKind::Linux);
    outcomes.extend(all_passing(&registry, 15, OsKind::Linux));
    assert_eq!(
        judge(check(check_id(13)), &outcomes, &context),
        CheckStatus::Refused {
            refusal: CheckRefusal::OtherCheck
        }
    );
    let mut twice = all_passing(&registry, 13, OsKind::Linux);
    twice.extend(all_passing(&registry, 13, OsKind::Linux));
    assert_eq!(
        judge(check(check_id(13)), &twice, &context),
        CheckStatus::Refused {
            refusal: CheckRefusal::DuplicatePart {
                part: Part::Primary
            }
        }
    );
}

#[test]
fn an_outcome_names_only_its_own_check_and_part() {
    let (registry, _clock) = registry();
    let foreign = ProbeOutcome::host(
        check_id(13),
        Part::Primary,
        HostKind::Host,
        registry.now(),
        FRESH,
        configuration("host-a"),
        RunResult::Observed {
            observations: observations(&[("cp15.links", refused())]),
        },
    );
    assert_eq!(
        foreign,
        Err(OutcomeError::ForeignExpectation {
            expectation: id("cp15.links"),
            check: check_id(13),
            part: Part::Primary
        })
    );
    let unknown_part = ProbeOutcome::not_tested(
        check_id(13),
        Part::Corroboration {
            fact: CorroboratingFact::BootedRootImage,
        },
        NotTestedReason::NotRun,
    );
    assert!(matches!(
        unknown_part,
        Err(OutcomeError::UnknownPart { .. })
    ));
}

// ---------------------------------------------------------------- guest reports

#[test]
fn a_guest_report_never_satisfies_a_host_only_check() {
    let (registry, _clock) = registry();
    let mut guest = GuestEnd::new(vm());
    let reports = guest.report(&[
        ("cp01.accelerator", GuestVerdict::Passed),
        ("cp01.forced-unavailable-refused", GuestVerdict::Passed),
        ("cp01.no-tcg-hypervisor", GuestVerdict::Passed),
        (
            "cp01.normal-launch-records-accelerator",
            GuestVerdict::Passed,
        ),
    ]);
    let outcome = guest_outcome(&registry, 1, Part::Primary, &reports).unwrap();
    assert_eq!(outcome.source_class(), Some(SourceClass::GuestReport));
    assert_eq!(
        judge(check(check_id(1)), &[outcome], &linux_context(&registry)),
        CheckStatus::Refused {
            refusal: CheckRefusal::WrongSource {
                part: Part::Primary,
                required: SourceKind::Host,
                found: SourceKind::Guest
            }
        }
    );
}

#[test]
fn a_forged_all_probes_passed_satisfies_nothing() {
    // VM-CP-25 (line 3175): a forged init or agent report claiming "all probes passed".
    let (registry, _clock) = registry();
    let mut guest = GuestEnd::new(vm());
    let mut reports = guest.send(&LinkMessage::AllProbesPassed(AllProbesPassed {
        probe_count: 40,
    }));
    reports.extend(guest.report(&[("cp15.links", GuestVerdict::Passed)]));
    let outcome = guest_outcome(&registry, 9, Part::Primary, &reports).unwrap();
    let Evidence::Guest { run } = outcome.evidence() else {
        panic!("not a guest run")
    };
    assert!(run.verdicts().is_empty());
    assert_eq!(run.source(), SourceClass::GuestReport);
    assert!(matches!(
        run.ignored(),
        [
            IgnoredClaim::AllProbesPassed {
                probe_count: 40,
                ..
            },
            IgnoredClaim::OtherProbe { .. }
        ]
    ));
    // Nothing the guest said is an observation of VM-CP-09, and its host corroboration is
    // missing: refused, never passed.
    let status = judge(check(check_id(9)), &[outcome], &linux_context(&registry));
    assert_eq!(
        status,
        CheckStatus::Refused {
            refusal: CheckRefusal::Uncorroborated {
                fact: CorroboratingFact::NoGuestNetworkDevice
            }
        }
    );
    let json = serde_json::to_value(&reports[0]).unwrap();
    assert_eq!(json["source"], "guest_report");
}

#[test]
fn a_guest_reported_check_passes_only_with_its_host_corroboration() {
    let (registry, _clock) = registry();
    let context = linux_context(&registry);
    let row = check(check_id(9));
    let mut guest = GuestEnd::new(vm());
    let reports = guest.report(&[
        ("cp09.direct-https-without-proxy", GuestVerdict::Passed),
        ("cp09.raw-socket", GuestVerdict::Passed),
        ("cp09.alternate-dns", GuestVerdict::Passed),
        ("cp09.approved-route-succeeds", GuestVerdict::Passed),
    ]);
    let primary = guest_outcome(&registry, 9, Part::Primary, &reports).unwrap();
    let corroboration = Part::Corroboration {
        fact: CorroboratingFact::NoGuestNetworkDevice,
    };
    let host_fact = host(
        &registry,
        9,
        corroboration,
        HostKind::Host,
        passing(9, corroboration, OsKind::Linux),
    );
    assert_eq!(
        judge(row, &[primary.clone(), host_fact.clone()], &context),
        CheckStatus::Passed
    );
    // Without it, refused; with the corroboration reported by the guest, refused too.
    assert_eq!(
        judge(row, &[primary.clone()], &context),
        CheckStatus::Refused {
            refusal: CheckRefusal::Uncorroborated {
                fact: CorroboratingFact::NoGuestNetworkDevice
            }
        }
    );
    let guest_corroboration = guest_outcome(
        &registry,
        9,
        corroboration,
        &guest.report(&[("cp09.packet-from-vm", GuestVerdict::Passed)]),
    )
    .unwrap();
    assert_eq!(
        judge(row, &[primary.clone(), guest_corroboration], &context),
        CheckStatus::Refused {
            refusal: CheckRefusal::WrongSource {
                part: corroboration,
                required: SourceKind::Host,
                found: SourceKind::Guest
            }
        }
    );
    // The host saw a packet: the corroboration fails, so the check fails.
    let saw_packet = host(
        &registry,
        9,
        corroboration,
        HostKind::Host,
        observations(&[("cp09.packet-from-vm", present())]),
    );
    assert_eq!(
        judge(row, &[primary.clone(), saw_packet], &context),
        CheckStatus::Failed {
            failure: Failure::Expectation {
                id: id("cp09.packet-from-vm"),
                part: corroboration
            }
        }
    );
    // A corroboration that was not run does not corroborate.
    let not_run = ProbeOutcome::not_tested(row.id, corroboration, NotTestedReason::NotRun).unwrap();
    assert_eq!(
        judge(row, &[primary, not_run], &context),
        CheckStatus::Refused {
            refusal: CheckRefusal::Uncorroborated {
                fact: CorroboratingFact::NoGuestNetworkDevice
            }
        }
    );
    let _ = host_fact;
}

#[test]
fn what_the_guest_says_failed_or_skipped_is_judged_as_such() {
    let (registry, _clock) = registry();
    let context = linux_context(&registry);
    let corroboration = Part::Corroboration {
        fact: CorroboratingFact::NoGuestNetworkDevice,
    };
    let host_fact = host(
        &registry,
        9,
        corroboration,
        HostKind::Host,
        passing(9, corroboration, OsKind::Linux),
    );
    for (verdict, expected) in [
        (
            GuestVerdict::Failed,
            CheckStatus::Failed {
                failure: Failure::Expectation {
                    id: id("cp09.raw-socket"),
                    part: Part::Primary,
                },
            },
        ),
        (
            GuestVerdict::Skipped,
            CheckStatus::Inconclusive {
                reason: InconclusiveReason::GuestSkipped {
                    id: id("cp09.raw-socket"),
                },
            },
        ),
        (
            GuestVerdict::Inconclusive,
            CheckStatus::Inconclusive {
                reason: InconclusiveReason::GuestInconclusive {
                    id: id("cp09.raw-socket"),
                },
            },
        ),
    ] {
        let mut guest = GuestEnd::new(vm());
        let reports = guest.report(&[
            ("cp09.direct-https-without-proxy", GuestVerdict::Passed),
            ("cp09.raw-socket", verdict),
            ("cp09.alternate-dns", GuestVerdict::Passed),
            ("cp09.approved-route-succeeds", GuestVerdict::Passed),
        ]);
        let primary = guest_outcome(&registry, 9, Part::Primary, &reports).unwrap();
        assert_eq!(
            judge(check(check_id(9)), &[primary, host_fact.clone()], &context),
            expected
        );
    }
}

#[test]
fn guest_reports_from_another_instance_or_repeated_are_refused() {
    let (registry, _clock) = registry();
    let mut other = GuestEnd::new(other_vm());
    let foreign = other.report(&[("cp09.raw-socket", GuestVerdict::Passed)]);
    assert!(matches!(
        guest_outcome(&registry, 9, Part::Primary, &foreign),
        Err(OutcomeError::OtherInstance { .. })
    ));
    let mut guest = GuestEnd::new(vm());
    let repeated = guest.report(&[
        ("cp09.raw-socket", GuestVerdict::Passed),
        ("cp09.raw-socket", GuestVerdict::Failed),
    ]);
    assert_eq!(
        guest_outcome(&registry, 9, Part::Primary, &repeated),
        Err(OutcomeError::DuplicateGuestResult {
            expectation: id("cp09.raw-socket")
        })
    );
}

// ---------------------------------------------------------------- CORE-01 adapters

fn cp01_runner(observations: Observations) -> ScriptedRunner {
    ScriptedRunner::new(configuration("host-a"), OsKind::Linux).answer(
        check_id(1),
        Part::Primary,
        RunResult::Observed { observations },
    )
}

#[test]
fn the_hypervisor_adapter_puts_host_evidence_in_the_registry() {
    let (mut registry, _clock) = registry();
    let runner = Arc::new(cp01_runner(passing(1, Part::Primary, OsKind::Linux)));
    registry
        .register(Box::new(HypervisorAvailableProbe::new(Arc::clone(&runner))))
        .unwrap();
    let subject = hypervisor_subject(HypervisorKind::Kvm);
    let envelope = registry
        .refresh(Capability::HypervisorAvailable, &subject)
        .unwrap();
    assert_eq!(envelope.source(), SourceClass::HostProbe);
    assert_eq!(
        *runner.calls.lock().unwrap(),
        [(check_id(1), Part::Primary)]
    );
    let requirement = Requirement::host_only(
        Capability::HypervisorAvailable,
        subject,
        MAX_AGE,
        configuration("host-a"),
    );
    let satisfied = registry.evaluate(&requirement).unwrap();
    assert_eq!(satisfied.source(), SourceClass::HostProbe);
    assert_eq!(hypervisor_of("whpx"), Some(HypervisorKind::Whpx));
    assert_eq!(hypervisor_of("tcg"), None);
}

#[test]
fn the_hypervisor_adapter_refuses_on_a_failure_and_is_unknown_without_its_control() {
    let subject = hypervisor_subject(HypervisorKind::Kvm);
    let observe = |observations: Observations| {
        let probe = HypervisorAvailableProbe::new(cp01_runner(observations));
        crate::foundation::evidence::ProbeAdapter::observe(&probe, &subject).result
    };
    // A launch that was not refused with the accelerator forced unavailable.
    let mut fell_back = passing(1, Part::Primary, OsKind::Linux);
    fell_back.insert(id("cp01.forced-unavailable-refused"), succeeded());
    assert_eq!(
        observe(fell_back),
        ObservationResult::Unsupported {
            reason: UnsupportedReason::HypervisorUnavailable
        }
    );
    // The normal launch failed: nothing is attributable.
    let mut no_control = passing(1, Part::Primary, OsKind::Linux);
    no_control.insert(id("cp01.normal-launch-records-accelerator"), refused());
    assert_eq!(
        observe(no_control),
        ObservationResult::Unknown {
            reason: UnknownReason::Inconclusive
        }
    );
    // The record names another hypervisor than the subject's.
    let mut other = passing(1, Part::Primary, OsKind::Linux);
    other.insert(id("cp01.accelerator"), value("whpx"));
    assert_eq!(
        observe(other),
        ObservationResult::Unknown {
            reason: UnknownReason::InconsistentReport
        }
    );
    // An unreachable subject.
    let unreachable = ScriptedRunner::new(configuration("host-a"), OsKind::Linux).answer(
        check_id(1),
        Part::Primary,
        RunResult::Inconclusive {
            reason: RunnerInconclusive::Unreachable,
        },
    );
    let probe = HypervisorAvailableProbe::new(unreachable);
    assert_eq!(
        crate::foundation::evidence::ProbeAdapter::observe(&probe, &subject).result,
        ObservationResult::Unknown {
            reason: UnknownReason::Unreachable
        }
    );
}

#[test]
fn the_perimeter_adapter_reports_enforcement_only_with_a_reached_control() {
    let subject = perimeter_subject();
    let observe = |result: RunResult| {
        let runner = ScriptedRunner::new(configuration("host-a"), OsKind::Linux).answer(
            check_id(11),
            Part::Primary,
            result,
        );
        crate::foundation::evidence::ProbeAdapter::observe(
            &PerimeterRuleProbe::new(runner),
            &subject,
        )
        .result
    };
    let observed = |observations: Observations| RunResult::Observed { observations };
    assert!(matches!(
        observe(observed(passing(11, Part::Primary, OsKind::Linux))),
        ObservationResult::Supported { .. }
    ));
    let mut got_through = passing(11, Part::Primary, OsKind::Linux);
    got_through.insert(id("cp11.broker-identity-blocked"), succeeded());
    assert_eq!(
        observe(observed(got_through)),
        ObservationResult::Unsupported {
            reason: UnsupportedReason::NotEnforced
        }
    );
    let mut unreached = passing(11, Part::Primary, OsKind::Linux);
    unreached.insert(id("cp11.broker-reaches-allowed-endpoint"), refused());
    assert_eq!(
        observe(observed(unreached)),
        ObservationResult::Unknown {
            reason: UnknownReason::Inconclusive
        }
    );
    assert_eq!(
        observe(RunResult::Inconclusive {
            reason: RunnerInconclusive::TimedOut
        }),
        ObservationResult::Unknown {
            reason: UnknownReason::Inconclusive
        }
    );
}

#[test]
fn guest_claimed_evidence_never_satisfies_a_host_only_requirement_in_the_registry() {
    let (mut registry, _clock) = registry();
    registry
        .register(Box::new(GuestClaimedHypervisor {
            configuration: configuration("host-a"),
        }))
        .unwrap();
    let subject = hypervisor_subject(HypervisorKind::Kvm);
    let envelope = registry
        .refresh(Capability::HypervisorAvailable, &subject)
        .unwrap();
    assert_eq!(envelope.source(), SourceClass::GuestReport);
    let requirement = Requirement::host_only(
        Capability::HypervisorAvailable,
        subject,
        MAX_AGE,
        configuration("host-a"),
    );
    assert!(matches!(
        registry.evaluate(&requirement),
        Err(EvidenceRefusal::SourceTooWeak { .. })
    ));
}

// ---------------------------------------------------------------- CORE-01 coverage map

#[test]
fn the_coverage_map_names_every_check_once_in_order() {
    let ids: Vec<u8> = core01_coverage()
        .iter()
        .map(|entry| entry.check.number())
        .collect();
    assert_eq!(ids, (1..=35).collect::<Vec<u8>>());
    for entry in core01_coverage() {
        assert_eq!(coverage_of(entry.check), &entry.coverage);
    }
}

#[test]
fn the_coverage_map_feeds_exactly_the_planned_capabilities() {
    let planned: BTreeMap<u8, Capability> = [
        (1, Capability::HypervisorAvailable),
        (2, Capability::HypervisorConfigurationMatches),
        (3, Capability::HypervisorConfigurationMatches),
        (4, Capability::HypervisorConfined),
        (5, Capability::BootedImageMatchesManifest),
        (7, Capability::DestinationPolicyEnforced),
        (8, Capability::DestinationPolicyEnforced),
        (9, Capability::NoGuestNetworkDevice),
        (11, Capability::PerimeterRuleEnforced),
        (12, Capability::CredentialAbsentFromScannedLocations),
        (17, Capability::BootedImageMatchesManifest),
        (21, Capability::CloneIdentityReset),
        (23, Capability::BootedImageMatchesManifest),
        (31, Capability::DeviceAssignmentIsolated),
    ]
    .into_iter()
    .collect();
    for entry in core01_coverage() {
        match (entry.coverage, planned.get(&entry.check.number())) {
            (Core01Coverage::Capability { capability, .. }, Some(expected)) => {
                assert_eq!(capability, *expected, "{}", entry.check);
                assert_eq!(capability.weakest_source(), SourceClass::HostProbe);
            }
            (Core01Coverage::NoCapability { covered_by, reason }, None) => {
                assert!(!reason.is_empty(), "{}", entry.check);
                let expected: &[Capability] = if entry.check.number() == 33 {
                    &[Capability::RuntimeCategory, Capability::HypervisorAvailable]
                } else {
                    &[]
                };
                assert_eq!(covered_by, expected, "{}", entry.check);
            }
            (coverage, expected) => panic!("{}: {coverage:?}, planned {expected:?}", entry.check),
        }
    }
    let fed: BTreeSet<Capability> = planned.values().copied().collect();
    assert_eq!(fed.len(), 10);
    for capability in fed {
        assert!(checks_for(capability).next().is_some(), "{capability}");
    }
}

#[test]
fn only_host_observed_parts_feed_a_capability() {
    for entry in core01_coverage() {
        let Core01Coverage::Capability { parts, .. } = entry.coverage else {
            continue;
        };
        let row = check(entry.check);
        // A guest-reported check feeds through its host corroboration, all of it and
        // nothing else; any other check through its own host-observed observation.
        let expected: Vec<Part> = if row.side.is_host_only() {
            vec![Part::Primary]
        } else {
            row.side
                .corroboration()
                .iter()
                .map(|fact| Part::Corroboration { fact: *fact })
                .collect()
        };
        assert_eq!(parts, expected.as_slice(), "{}", entry.check);
        for part in parts {
            assert_eq!(
                row.side.required_source(*part),
                Some(SourceKind::Host),
                "{} {part}",
                entry.check
            );
            for os in OSES {
                assert!(
                    !row.runs_on(os) || row.observations_for(*part, os).next().is_some(),
                    "{} {part} has nothing to observe on {os}",
                    entry.check
                );
            }
        }
    }
}

// ---------------------------------------------------------------- every CORE-01 adapter

/// Builds an adapter around a scripted runner.
type MakeAdapter = fn(Arc<ScriptedRunner>) -> Box<dyn ProbeAdapter>;

/// One adapter with the refusal and the detail it reports.
struct Case {
    capability: Capability,
    make: MakeAdapter,
    refusal: UnsupportedReason,
    detail: SupportDetail,
}

fn cases() -> Vec<Case> {
    vec![
        Case {
            capability: Capability::HypervisorAvailable,
            make: |runner| Box::new(HypervisorAvailableProbe::new(runner)),
            refusal: UnsupportedReason::HypervisorUnavailable,
            detail: SupportDetail::Hypervisor {
                hypervisor: HypervisorKind::Kvm,
            },
        },
        Case {
            capability: Capability::PerimeterRuleEnforced,
            make: |runner| Box::new(PerimeterRuleProbe::new(runner)),
            refusal: UnsupportedReason::NotEnforced,
            detail: SupportDetail::PerimeterRuleEnforced,
        },
        Case {
            capability: Capability::HypervisorConfigurationMatches,
            make: |runner| Box::new(HypervisorConfigurationMatchesProbe::new(runner)),
            refusal: UnsupportedReason::ConfigurationNotApproved,
            detail: SupportDetail::Plain,
        },
        Case {
            capability: Capability::HypervisorConfined,
            make: |runner| Box::new(HypervisorConfinedProbe::new(runner)),
            refusal: UnsupportedReason::NotConfined,
            detail: SupportDetail::Plain,
        },
        Case {
            capability: Capability::BootedImageMatchesManifest,
            make: |runner| Box::new(BootedImageMatchesManifestProbe::new(runner)),
            refusal: UnsupportedReason::ImageNotAsSigned,
            detail: SupportDetail::Plain,
        },
        Case {
            capability: Capability::DestinationPolicyEnforced,
            make: |runner| Box::new(DestinationPolicyEnforcedProbe::new(runner)),
            refusal: UnsupportedReason::DestinationNotRefused,
            detail: SupportDetail::Plain,
        },
        Case {
            capability: Capability::NoGuestNetworkDevice,
            make: |runner| Box::new(NoGuestNetworkDeviceProbe::new(runner)),
            refusal: UnsupportedReason::GuestNetworkPath,
            detail: SupportDetail::Plain,
        },
        Case {
            capability: Capability::CredentialAbsentFromScannedLocations,
            make: |runner| Box::new(CredentialAbsentFromScannedLocationsProbe::new(runner)),
            refusal: UnsupportedReason::CredentialExposed,
            detail: SupportDetail::Plain,
        },
        Case {
            capability: Capability::CloneIdentityReset,
            make: |runner| Box::new(CloneIdentityResetProbe::new(runner)),
            refusal: UnsupportedReason::CloneIdentityShared,
            detail: SupportDetail::Plain,
        },
        Case {
            capability: Capability::DeviceAssignmentIsolated,
            make: |runner| Box::new(DeviceAssignmentIsolatedProbe::new(runner)),
            refusal: UnsupportedReason::DeviceNotIsolated,
            detail: SupportDetail::Plain,
        },
    ]
}

/// One subject of every kind; the hypervisor is KVM, which the passing VM-CP-01 run names.
fn subjects() -> Vec<Subject> {
    let part = |name: &[u8]| digest("yougori/test/probes/subject/v1", &[name]);
    let machine = part(b"machine");
    let launch = SandboxBootSubject {
        machine,
        vm: part(b"vm"),
        boot: boot(),
    };
    let runtime = RuntimeSubject {
        category: ExecutionCategory::VmSandbox,
        release: BackendRelease::new(Backend::Vllm, "0.31.0").unwrap(),
        instance: part(b"runtime"),
    };
    vec![
        Subject::Host(HostSubject { machine }),
        Subject::GpuDevice(GpuDeviceSubject {
            machine,
            device: part(b"gpu-a"),
        }),
        hypervisor_subject(HypervisorKind::Kvm),
        Subject::OperatingSystem(OperatingSystemSubject {
            machine,
            os: OsKind::Linux,
        }),
        Subject::Provider(ProviderSubject {
            provider: ProviderKind::RunPod,
            resource: part(b"pod"),
        }),
        Subject::Runtime(runtime.clone()),
        Subject::GpuPair(GpuPairSubject {
            machine,
            from: part(b"gpu-a"),
            to: part(b"gpu-b"),
        }),
        Subject::ModelCheckpoint(ModelCheckpointSubject {
            checkpoint: part(b"checkpoint"),
            release: runtime.release.clone(),
            image: part(b"image"),
            hardware: part(b"hardware"),
        }),
        Subject::CudaAllocation(CudaAllocationSubject {
            runtime,
            device_ordinal: 0,
            requested_handle: None,
        }),
        perimeter_subject(),
        Subject::SandboxBoot(launch),
        Subject::HypervisorProcess(HypervisorProcessSubject {
            launch,
            process: part(b"hypervisor-process"),
        }),
        Subject::TransportBroker(TransportBrokerSubject {
            machine,
            perimeter: part(b"perimeter"),
            broker: part(b"broker"),
            policy: part(b"destination-policy"),
        }),
        Subject::CredentialScan(CredentialScanSubject {
            launch,
            locations: part(b"scanned-locations"),
        }),
        Subject::SnapshotClones(SnapshotClonesSubject {
            machine,
            snapshot: part(b"golden"),
            clones: part(b"two-clones"),
        }),
    ]
}

fn subject_for(capability: Capability) -> Subject {
    subjects()
        .into_iter()
        .find(|subject| subject.kind() == capability.subject_kind())
        .unwrap_or_else(|| panic!("no subject for {capability}"))
}

/// What the runner answers, per check and part.
type Script = BTreeMap<(CheckId, Part), RunResult>;

/// Every part `capability`'s checks feed, in coverage order.
fn fed_parts(capability: Capability) -> Vec<(CheckId, Part)> {
    checks_for(capability)
        .flat_map(|(check_id, parts)| parts.iter().map(move |part| (check_id, *part)))
        .collect()
}

/// A script in which every fed part passes on `os`, its positive control included.
fn passing_script(capability: Capability, os: OsKind) -> Script {
    fed_parts(capability)
        .into_iter()
        .map(|(check_id, part)| {
            (
                (check_id, part),
                RunResult::Observed {
                    observations: passing(check_id.number(), part, os),
                },
            )
        })
        .collect()
}

fn runner_for(script: &Script, os: OsKind) -> ScriptedRunner {
    script.iter().fold(
        ScriptedRunner::new(configuration("host-a"), os),
        |runner, ((check_id, part), result)| runner.answer(*check_id, *part, result.clone()),
    )
}

fn observations_in(script: &mut Script, check_id: CheckId, part: Part) -> &mut Observations {
    match script.get_mut(&(check_id, part)) {
        Some(RunResult::Observed { observations }) => observations,
        _ => panic!("nothing observed for {check_id} {part}"),
    }
}

/// The result one refresh of `case` stamps, through a fresh registry.
fn refreshed(case: &Case, script: &Script, os: OsKind) -> ObservationResult {
    let (mut registry, _clock) = registry();
    registry
        .register((case.make)(Arc::new(runner_for(script, os))))
        .unwrap();
    registry
        .refresh(case.capability, &subject_for(case.capability))
        .unwrap()
        .result()
        .clone()
}

fn unknown(reason: UnknownReason) -> ObservationResult {
    ObservationResult::Unknown { reason }
}

#[test]
fn every_adapter_runs_its_host_parts_live_and_satisfies_a_host_only_requirement() {
    for case in cases() {
        for os in OSES {
            let (mut registry, _clock) = registry();
            let runner = Arc::new(runner_for(&passing_script(case.capability, os), os));
            let adapter = (case.make)(Arc::clone(&runner));
            assert_eq!(adapter.capability(), case.capability);
            assert_eq!(adapter.source(), SourceClass::HostProbe);
            assert!(adapter.host_changes().is_empty());
            registry.register(adapter).unwrap();
            let subject = subject_for(case.capability);
            let envelope = registry.refresh(case.capability, &subject).unwrap();
            assert_eq!(
                envelope.source(),
                SourceClass::HostProbe,
                "{}",
                case.capability
            );
            // A capability whose checks this host cannot run (VM-CP-31 off Linux) is not
            // tested, and nothing is run.
            let runs_here = fed_parts(case.capability)
                .iter()
                .all(|(check_id, _)| check(*check_id).runs_on(os));
            if !runs_here {
                assert_eq!(
                    envelope.result(),
                    &unknown(UnknownReason::NotTested),
                    "{} on {os}",
                    case.capability
                );
                assert!(runner.calls.lock().unwrap().is_empty());
                continue;
            }
            assert_eq!(
                envelope.result(),
                &ObservationResult::Supported {
                    detail: case.detail.clone()
                },
                "{} on {os}",
                case.capability
            );
            let calls = runner.calls.lock().unwrap().clone();
            assert_eq!(calls, fed_parts(case.capability), "{}", case.capability);
            for (check_id, part) in &calls {
                assert_eq!(
                    check(*check_id).side.required_source(*part),
                    Some(SourceKind::Host)
                );
            }
            // A second refresh runs the checks again rather than replaying the first.
            registry.refresh(case.capability, &subject).unwrap();
            assert_eq!(runner.calls.lock().unwrap().len(), 2 * calls.len());
            let requirement =
                Requirement::host_only(case.capability, subject, MAX_AGE, configuration("host-a"));
            let satisfied = registry.evaluate(&requirement).unwrap();
            assert_eq!(satisfied.source(), SourceClass::HostProbe);
            assert_eq!(satisfied.detail(), &case.detail);
        }
    }
}

#[test]
fn a_guest_report_never_satisfies_any_boundary_capability() {
    for case in cases() {
        let (mut registry, _clock) = registry();
        registry
            .register(Box::new(GuestClaimed {
                capability: case.capability,
                detail: case.detail.clone(),
                configuration: configuration("host-a"),
            }))
            .unwrap();
        let subject = subject_for(case.capability);
        let envelope = registry.refresh(case.capability, &subject).unwrap();
        assert_eq!(envelope.source(), SourceClass::GuestReport);
        assert!(matches!(
            envelope.result(),
            ObservationResult::Supported { .. }
        ));
        for minimum in [SourceClass::HostProbe, SourceClass::GuestReport] {
            let requirement = Requirement::new(
                case.capability,
                subject.clone(),
                minimum,
                MAX_AGE,
                configuration("host-a"),
            );
            assert!(requirement.is_host_only(), "{}", case.capability);
            assert_eq!(
                registry.evaluate(&requirement),
                Err(EvidenceRefusal::SourceTooWeak {
                    capability: case.capability,
                    observed: SourceClass::GuestReport,
                    required: SourceClass::HostProbe,
                }),
                "{}",
                case.capability
            );
        }
    }
}

#[test]
fn every_adapter_is_unknown_without_its_positive_control() {
    let mut without_control = BTreeSet::new();
    for case in cases() {
        let mut controls = 0;
        for (check_id, part) in fed_parts(case.capability) {
            let Some(control) = check(check_id).control().filter(|c| c.part == part) else {
                continue;
            };
            controls += 1;
            let mut missing = passing_script(case.capability, OsKind::Linux);
            observations_in(&mut missing, check_id, part).remove(&control.id);
            let mut failed = passing_script(case.capability, OsKind::Linux);
            observations_in(&mut failed, check_id, part)
                .insert(control.id, violating(control.expect));
            for script in [missing, failed] {
                assert_eq!(
                    refreshed(&case, &script, OsKind::Linux),
                    unknown(UnknownReason::Inconclusive),
                    "{} {check_id}",
                    case.capability
                );
            }
        }
        if controls == 0 {
            without_control.insert(case.capability);
        }
    }
    // §17 lists no positive control for VM-CP-12 or VM-CP-21, and VM-CP-09's control
    // belongs to its guest-reported part.
    assert_eq!(
        without_control,
        BTreeSet::from([
            Capability::NoGuestNetworkDevice,
            Capability::CredentialAbsentFromScannedLocations,
            Capability::CloneIdentityReset,
        ])
    );
}

#[test]
fn every_failing_observation_refuses_with_the_capabilitys_reason() {
    for case in cases() {
        for os in OSES {
            for (check_id, part) in fed_parts(case.capability) {
                for entry in check(check_id).observations_for(part, os) {
                    let mut script = passing_script(case.capability, os);
                    observations_in(&mut script, check_id, part)
                        .insert(entry.id, violating(entry.expect));
                    assert_eq!(
                        refreshed(&case, &script, os),
                        ObservationResult::Unsupported {
                            reason: case.refusal
                        },
                        "{} {} on {os}",
                        case.capability,
                        entry.id
                    );
                }
            }
        }
        // The refusal reaches the requirement with its remedy.
        let (mut registry, _clock) = registry();
        let mut script = passing_script(case.capability, OsKind::Linux);
        let (check_id, part) = fed_parts(case.capability)[0];
        let first = check(check_id)
            .observations_for(part, OsKind::Linux)
            .next()
            .unwrap();
        observations_in(&mut script, check_id, part).insert(first.id, violating(first.expect));
        registry
            .register((case.make)(Arc::new(runner_for(&script, OsKind::Linux))))
            .unwrap();
        let subject = subject_for(case.capability);
        registry.refresh(case.capability, &subject).unwrap();
        let refusal = registry
            .evaluate(&Requirement::host_only(
                case.capability,
                subject,
                MAX_AGE,
                configuration("host-a"),
            ))
            .unwrap_err();
        assert_eq!(
            refusal,
            EvidenceRefusal::Unsupported {
                capability: case.capability,
                reason: case.refusal
            }
        );
        assert_eq!(refusal.remedy(), case.refusal.remedy());
    }
}

/// An observation of another kind than `expect` judges.
fn ill_typed(expect: Expect) -> Observed {
    if expect.judges() == ObservedKind::Presence {
        happened()
    } else {
        present()
    }
}

#[test]
fn a_run_that_did_not_finish_or_reported_badly_is_unknown() {
    let foreign = id("cp13.provider-call");
    for case in cases() {
        for (check_id, part) in fed_parts(case.capability) {
            let inconclusive = |reason| {
                let mut script = passing_script(case.capability, OsKind::Linux);
                script.insert((check_id, part), RunResult::Inconclusive { reason });
                refreshed(&case, &script, OsKind::Linux)
            };
            assert_eq!(
                inconclusive(RunnerInconclusive::Unreachable),
                unknown(UnknownReason::Unreachable),
                "{} {check_id}",
                case.capability
            );
            for reason in [
                RunnerInconclusive::TimedOut,
                RunnerInconclusive::Interrupted,
            ] {
                assert_eq!(inconclusive(reason), unknown(UnknownReason::Inconclusive));
            }
            let entry = check(check_id)
                .observations_for(part, OsKind::Linux)
                .next()
                .unwrap();
            let mut missing = passing_script(case.capability, OsKind::Linux);
            observations_in(&mut missing, check_id, part).remove(&entry.id);
            assert_eq!(
                refreshed(&case, &missing, OsKind::Linux),
                unknown(UnknownReason::Inconclusive),
                "{} {}",
                case.capability,
                entry.id
            );
            let mut wrong_kind = passing_script(case.capability, OsKind::Linux);
            observations_in(&mut wrong_kind, check_id, part)
                .insert(entry.id, ill_typed(entry.expect));
            assert_eq!(
                refreshed(&case, &wrong_kind, OsKind::Linux),
                unknown(UnknownReason::InconsistentReport),
                "{} {}",
                case.capability,
                entry.id
            );
            let mut misplaced = passing_script(case.capability, OsKind::Linux);
            observations_in(&mut misplaced, check_id, part).insert(foreign, absent());
            assert_eq!(
                refreshed(&case, &misplaced, OsKind::Linux),
                unknown(UnknownReason::InconsistentReport),
                "{} {check_id}",
                case.capability
            );
        }
    }
}

#[test]
fn every_adapter_observes_only_its_own_subject_kind() {
    let kinds: BTreeSet<SubjectKind> = subjects().iter().map(Subject::kind).collect();
    assert_eq!(kinds.len(), subjects().len());
    for case in cases() {
        let runner = Arc::new(runner_for(
            &passing_script(case.capability, OsKind::Linux),
            OsKind::Linux,
        ));
        let adapter = (case.make)(Arc::clone(&runner));
        let (mut registry, _clock) = registry();
        registry.register((case.make)(Arc::clone(&runner))).unwrap();
        for subject in subjects() {
            if subject.kind() == case.capability.subject_kind() {
                assert!(adapter.observes(&subject));
                continue;
            }
            assert!(
                !adapter.observes(&subject),
                "{} {subject:?}",
                case.capability
            );
            assert_eq!(
                adapter.observe(&subject).result,
                unknown(UnknownReason::InconsistentReport)
            );
            assert!(matches!(
                registry.refresh(case.capability, &subject),
                Err(RegistryError::WrongSubjectKind { .. })
            ));
        }
        assert!(
            runner.calls.lock().unwrap().is_empty(),
            "{}",
            case.capability
        );
    }
}

#[test]
fn the_confinement_adapter_judges_only_the_hosts_own_observations() {
    let case = cases()
        .into_iter()
        .find(|case| case.capability == Capability::HypervisorConfined)
        .unwrap();
    // WSL2 has no VM-CP-04 observation of its own: not tested, never supported.
    let runner = Arc::new(runner_for(
        &passing_script(case.capability, OsKind::Linux),
        OsKind::Wsl2,
    ));
    let adapter = (case.make)(Arc::clone(&runner));
    assert_eq!(
        adapter.observe(&subject_for(case.capability)).result,
        unknown(UnknownReason::NotTested)
    );
    assert!(runner.calls.lock().unwrap().is_empty());
    // Linux observations do not stand for the Windows ones.
    assert_eq!(
        refreshed(
            &case,
            &passing_script(case.capability, OsKind::Linux),
            OsKind::Windows
        ),
        unknown(UnknownReason::Inconclusive)
    );
}

// ---------------------------------------------------------------- VM-CP-05 from V15

fn verdict(outcome: VerdictOutcome, checks: Vec<CheckVerdict>) -> ConfinementVerdict {
    ConfinementVerdict {
        profile: digest("yougori/test/probes/profile/v1", &[b"strict-tool"]),
        workload: WorkloadProfile::StrictTool,
        meaning: VerdictMeaning::InnerControlsDefenseInDepth,
        host_corroboration_required: true,
        checks,
        outcome,
    }
}

fn verdict_check(
    check: ConfinementCheck,
    source: SourceClass,
    outcome: CheckOutcome,
) -> CheckVerdict {
    CheckVerdict {
        check,
        source,
        required: true,
        outcome,
    }
}

#[test]
fn vm_cp_05_follows_the_v15_verdict_and_never_passes_on_guest_reports_alone() {
    assert_eq!(
        status_of_verdict(&verdict(VerdictOutcome::Passed, Vec::new())),
        CheckStatus::Passed
    );
    assert_eq!(
        status_of_verdict(&verdict(VerdictOutcome::GuestReportedOnly, Vec::new())),
        CheckStatus::Refused {
            refusal: CheckRefusal::GuestReportedOnly
        }
    );
    let failed = verdict(
        VerdictOutcome::Failed,
        vec![
            verdict_check(
                ConfinementCheck::HostKernelRecord,
                SourceClass::HostProbe,
                CheckOutcome::Inconclusive {
                    reason: ConfinementInconclusive::NoHostCorroboration,
                },
            ),
            verdict_check(
                ConfinementCheck::ReportProfile,
                SourceClass::GuestReport,
                CheckOutcome::Failed {
                    reason: FailureReason::ProfileMismatch {
                        reported: digest("yougori/test/probes/profile/v1", &[b"other"]),
                    },
                },
            ),
        ],
    );
    assert_eq!(
        status_of_verdict(&failed),
        CheckStatus::Failed {
            failure: Failure::Confinement {
                check: ConfinementCheck::ReportProfile
            }
        }
    );
    let open = verdict(
        VerdictOutcome::Failed,
        vec![verdict_check(
            ConfinementCheck::HostRootImage,
            SourceClass::HostProbe,
            CheckOutcome::Inconclusive {
                reason: ConfinementInconclusive::NoHostCorroboration,
            },
        )],
    );
    assert_eq!(
        status_of_verdict(&open),
        CheckStatus::Inconclusive {
            reason: InconclusiveReason::Confinement {
                check: ConfinementCheck::HostRootImage
            }
        }
    );
    assert_eq!(
        status_of_verdict(&verdict(VerdictOutcome::Failed, Vec::new())),
        CheckStatus::Inconclusive {
            reason: InconclusiveReason::ConfinementVerdictInconsistent
        }
    );
}

#[test]
fn a_stale_vm_cp_05_verdict_is_refused() {
    let (registry, clock) = registry();
    let evaluation = Vm05Evaluation::evaluated(
        verdict(VerdictOutcome::Passed, Vec::new()),
        registry.now(),
        FRESH,
        configuration("host-a"),
    );
    assert_eq!(
        evaluation.status(&linux_context(&registry)),
        CheckStatus::Passed
    );
    clock.advance(MAX_AGE + Duration::from_secs(1));
    assert!(matches!(
        evaluation.status(&linux_context(&registry)),
        CheckStatus::Refused {
            refusal: CheckRefusal::NotCurrent { .. }
        }
    ));
    assert!(matches!(
        evaluation.status(&context(&registry, configuration("host-b"), OsKind::Linux)),
        CheckStatus::Refused {
            refusal: CheckRefusal::NotCurrent {
                problem: ObservationProblem::OtherConfiguration { .. },
                ..
            }
        }
    ));
}

// ---------------------------------------------------------------- the report

/// Inputs that pass every check on Linux, with VM-CP-05 from a passing V15 verdict.
fn passing_inputs(registry: &ProbeRegistry<Arc<ManualClock>>) -> BTreeMap<CheckId, CheckInput> {
    let mut inputs: BTreeMap<CheckId, CheckInput> = catalog()
        .iter()
        .map(|row| {
            (
                row.id,
                CheckInput::Outcomes(all_passing(registry, row.id.number(), OsKind::Linux)),
            )
        })
        .collect();
    inputs.insert(
        check_id(5),
        CheckInput::Vm05(Vm05Evaluation::evaluated(
            verdict(VerdictOutcome::Passed, Vec::new()),
            registry.now(),
            FRESH,
            configuration("host-a"),
        )),
    );
    inputs
}

#[test]
fn a_report_lists_every_check_and_allows_launch_only_when_every_required_check_passed() {
    let (registry, _clock) = registry();
    let context = linux_context(&registry);
    let profile = linux_profile(&[RunProfile::Strict]);
    let report =
        BoundaryReport::assemble(profile.clone(), passing_inputs(&registry), &context).unwrap();
    assert_eq!(report.entries().len(), 35);
    assert!(report.allows_launch());
    assert!(report.unsatisfied().is_empty());
    assert_eq!(report.gpu(), &GpuPath::NotRequested);
    // Strict requires VM-CP-04; the GPU VM check is not required for this profile.
    assert_eq!(
        report.entry(check_id(4)).unwrap().applicability,
        Applicability::Required
    );
    assert_eq!(
        report.entry(check_id(31)).unwrap().applicability,
        Applicability::NotRequired
    );

    // Nothing for VM-CP-08: not tested, blocking, and the network and evidence facets
    // are unsatisfied because of it.
    let mut inputs = passing_inputs(&registry);
    inputs.remove(&check_id(8));
    let report = BoundaryReport::assemble(profile, inputs, &context).unwrap();
    assert!(!report.allows_launch());
    let blocking: Vec<CheckId> = report.blocking().map(|entry| entry.check).collect();
    assert_eq!(blocking, [check_id(8)]);
    assert_eq!(
        report.entry(check_id(8)).unwrap().status,
        CheckStatus::NotTested {
            reason: NotTestedReason::NotRun
        }
    );
    let facets: Vec<Facet> = report
        .unsatisfied()
        .iter()
        .map(|facet| facet.facet)
        .collect();
    assert_eq!(facets, [Facet::NetworkAuthority, Facet::Evidence]);
    assert!(report
        .unsatisfied()
        .iter()
        .all(|facet| facet.because == [check_id(8)]));
}

#[test]
fn a_report_explains_an_unavailable_gpu_path() {
    let (registry, _clock) = registry();
    let context = linux_context(&registry);
    let profile = linux_profile(&[RunProfile::Strict, RunProfile::GpuVm]);
    let mut inputs = passing_inputs(&registry);
    inputs.insert(
        check_id(31),
        CheckInput::Outcomes(vec![ProbeOutcome::not_tested(
            check_id(31),
            Part::Primary,
            NotTestedReason::UnavailableHardware,
        )
        .unwrap()]),
    );
    let report = BoundaryReport::assemble(profile.clone(), inputs, &context).unwrap();
    match report.gpu() {
        GpuPath::Unavailable { status, why } => {
            assert!(!status.passed());
            assert!(why.contains("no GPU hardware"), "{why}");
        }
        other => panic!("{other:?}"),
    }
    assert!(!report.allows_launch());
    assert!(report
        .unsatisfied()
        .iter()
        .any(|facet| facet.facet == Facet::DeviceExposure && facet.because == [check_id(31)]));

    // A display-owning GPU: the refusal is named.
    let mut observations = passing(31, Part::Primary, OsKind::Linux);
    observations.insert(id("cp31.display-owning-gpu"), succeeded());
    let mut inputs = passing_inputs(&registry);
    inputs.insert(
        check_id(31),
        CheckInput::Outcomes(vec![host(
            &registry,
            31,
            Part::Primary,
            HostKind::Host,
            observations,
        )]),
    );
    let report = BoundaryReport::assemble(profile.clone(), inputs, &context).unwrap();
    match report.gpu() {
        GpuPath::Unavailable { why, .. } => assert!(why.contains("display-owning GPU"), "{why}"),
        other => panic!("{other:?}"),
    }
    // A passing VM-CP-31 makes it available.
    let report = BoundaryReport::assemble(profile, passing_inputs(&registry), &context).unwrap();
    assert_eq!(report.gpu(), &GpuPath::Available);
}

#[test]
fn a_report_identity_changes_with_any_outcome_and_a_new_configuration_needs_a_new_report() {
    let (registry, clock) = registry();
    let context = linux_context(&registry);
    let profile = linux_profile(&[RunProfile::Strict]);
    let first =
        BoundaryReport::assemble(profile.clone(), passing_inputs(&registry), &context).unwrap();
    let again =
        BoundaryReport::assemble(profile.clone(), passing_inputs(&registry), &context).unwrap();
    assert_eq!(first.identity(), again.identity());
    let mut inputs = passing_inputs(&registry);
    inputs.insert(
        check_id(22),
        CheckInput::Outcomes(vec![ProbeOutcome::not_tested(
            check_id(22),
            Part::Primary,
            NotTestedReason::NotRun,
        )
        .unwrap()]),
    );
    let changed = BoundaryReport::assemble(profile, inputs, &context).unwrap();
    assert_ne!(first.identity(), changed.identity());

    assert_eq!(
        first.current_at(registry.now(), MAX_AGE, configuration("host-a")),
        Ok(())
    );
    assert!(matches!(
        first.current_at(registry.now(), MAX_AGE, configuration("host-b")),
        Err(ObservationProblem::OtherConfiguration { .. })
    ));
    clock.advance(MAX_AGE + Duration::from_secs(1));
    assert!(matches!(
        first.current_at(registry.now(), MAX_AGE, configuration("host-a")),
        Err(ObservationProblem::Stale { .. })
    ));
}

#[test]
fn a_report_refuses_another_host_and_a_misplaced_verdict_and_states_no_score() {
    let (registry, _clock) = registry();
    let profile = linux_profile(&[RunProfile::Strict]);
    assert_eq!(
        BoundaryReport::assemble(
            profile.clone(),
            BTreeMap::new(),
            &context_for_os(&registry, OsKind::Windows)
        ),
        Err(ReportError::OtherHost {
            profile: OsKind::Linux,
            context: OsKind::Windows
        })
    );
    let mut inputs = BTreeMap::new();
    inputs.insert(
        check_id(6),
        CheckInput::Vm05(Vm05Evaluation::evaluated(
            verdict(VerdictOutcome::Passed, Vec::new()),
            registry.now(),
            FRESH,
            configuration("host-a"),
        )),
    );
    assert_eq!(
        BoundaryReport::assemble(profile.clone(), inputs, &linux_context(&registry)),
        Err(ReportError::Vm05ForOtherCheck { check: check_id(6) })
    );
    // Assembling changes nothing in the registry, and the record carries its notice and no
    // score.
    let before = registry.evidence().len();
    let report = BoundaryReport::assemble(
        profile,
        passing_inputs(&registry),
        &linux_context(&registry),
    )
    .unwrap();
    assert_eq!(registry.evidence().len(), before);
    let json = serde_json::to_string(&report).unwrap();
    assert!(json.contains("not a security certificate"));
    assert!(!json.to_lowercase().contains("score"));
    assert!(serde_json::to_value(&report).unwrap()["identity"].is_string());
}

#[test]
fn the_table_keeps_the_plan_scopes_for_per_platform_observations() {
    assert_eq!(
        expectation(id("cp04.windows.job-limits")).unwrap().scope,
        HostScope::Only(OsKind::Windows)
    );
    assert_eq!(
        expectation(id("cp11.macos.pf-counter-increases"))
            .unwrap()
            .scope,
        HostScope::Only(OsKind::MacOs)
    );
    assert_eq!(
        expectation(id("cp33.linux.kvm-unavailable")).unwrap().scope,
        HostScope::Only(OsKind::Linux)
    );
    assert_eq!(
        expectation(id("cp01.accelerator")).unwrap().expect,
        Expect::OneOf(super::expect::VM_CP_01_ACCELERATORS)
    );
}

#[test]
fn a_later_report_states_what_changed_since_an_earlier_one() {
    // VM-W23 (line 2622): "Report changes without altering host settings silently".
    let (registry, _clock) = registry();
    let context = linux_context(&registry);
    let profile = linux_profile(&[RunProfile::Strict]);
    let earlier =
        BoundaryReport::assemble(profile.clone(), passing_inputs(&registry), &context).unwrap();
    assert_eq!(
        earlier.changes_since(&earlier).unwrap(),
        super::report::ReportChanges {
            configuration_changed: false,
            launch_allowed_before: true,
            launch_allowed_now: true,
            checks: Vec::new(),
        }
    );

    // The perimeter check now fails under a new configuration.
    let reconfigured = context_with(&registry, "host-b");
    let mut inputs = BTreeMap::new();
    for row in catalog() {
        let outcomes = row
            .parts()
            .into_iter()
            .map(|part| {
                let mut observations = passing(row.id.number(), part, OsKind::Linux);
                if row.id == check_id(11) && part == Part::Primary {
                    observations.insert(id("cp11.broker-identity-blocked"), succeeded());
                }
                ProbeOutcome::host(
                    row.id,
                    part,
                    kind_for(row.id.number()),
                    registry.now(),
                    FRESH,
                    configuration("host-b"),
                    RunResult::Observed { observations },
                )
                .unwrap()
            })
            .collect();
        inputs.insert(row.id, CheckInput::Outcomes(outcomes));
    }
    inputs.insert(
        check_id(5),
        CheckInput::Vm05(Vm05Evaluation::evaluated(
            verdict(VerdictOutcome::Passed, Vec::new()),
            registry.now(),
            FRESH,
            configuration("host-b"),
        )),
    );
    let later = BoundaryReport::assemble(profile, inputs, &reconfigured).unwrap();
    let changes = later.changes_since(&earlier).unwrap();
    assert!(changes.configuration_changed);
    assert!(changes.launch_allowed_before && !changes.launch_allowed_now);
    assert_eq!(changes.checks.len(), 1);
    assert_eq!(changes.checks[0].check, check_id(11));
    assert_eq!(changes.checks[0].before, CheckStatus::Passed);
    assert!(matches!(
        changes.checks[0].after,
        CheckStatus::Failed { .. }
    ));

    // A report of another backend is not compared.
    let mut other = linux_profile(&[RunProfile::Strict]);
    other.backend = BackendKind::Qemu;
    let elsewhere = BoundaryReport::assemble(other, passing_inputs(&registry), &context).unwrap();
    assert_eq!(
        elsewhere.changes_since(&earlier),
        Err(ReportError::OtherProfile)
    );
}

fn context_with(registry: &ProbeRegistry<Arc<ManualClock>>, host: &str) -> JudgeContext {
    context(registry, configuration(host), OsKind::Linux)
}

// ---------------------------------------------------------------- report currency (R3)

/// Review finding R3, first counterexample: inputs observed at time 0 under a reader
/// limit of 300 s, a passing report assembled at 299 s. At 301 s the inputs are too old,
/// and the two-second-old report is not current either.
#[test]
fn assembling_a_report_does_not_renew_its_observations() {
    let (registry, clock) = registry();
    let inputs = passing_inputs(&registry);
    clock.advance(MAX_AGE - Duration::from_secs(1));
    let report = BoundaryReport::assemble(
        linux_profile(&[RunProfile::Strict]),
        inputs.clone(),
        &linux_context(&registry),
    )
    .unwrap();
    assert!(
        report.allows_launch(),
        "positive control: inputs still current at assembly"
    );
    assert_eq!(
        report.current_at(registry.now(), MAX_AGE, configuration("host-a")),
        Ok(()),
        "positive control: the report is current when assembled"
    );
    let window = report.evidence_window().unwrap();
    assert_eq!(
        registry
            .now()
            .at()
            .saturating_duration_since(window.observed_at),
        MAX_AGE - Duration::from_secs(1)
    );
    assert_eq!(
        window
            .valid_until
            .saturating_duration_since(window.observed_at),
        FRESH
    );
    // Every judged check carries the same window; a check this host cannot run has none.
    assert!(report.entries().iter().all(|entry| match entry.status {
        CheckStatus::Passed => entry.evidence == Some(window),
        CheckStatus::NotTested { .. } => entry.evidence.is_none(),
        ref other => panic!("{other:?}"),
    }));

    clock.advance(Duration::from_secs(2));
    let rejudged = BoundaryReport::assemble(
        linux_profile(&[RunProfile::Strict]),
        inputs,
        &linux_context(&registry),
    )
    .unwrap();
    assert!(
        !rejudged.allows_launch(),
        "positive control: the same inputs are now expired"
    );
    let cached = report.current_at(registry.now(), MAX_AGE, configuration("host-a"));
    assert_eq!(
        cached,
        Err(ObservationProblem::Stale {
            staleness: Staleness::TooOld {
                age: MAX_AGE + Duration::from_secs(1),
                limit: MAX_AGE,
            }
        }),
        "a cached report must not outlive its evidence"
    );
    // The rejudged report rests on refused evidence only, so nothing in it can expire;
    // it is current as a record of refusals and says that every check was refused.
    assert!(rejudged.evidence_window().is_none());
    assert!(rejudged.entries().iter().all(
        |entry| entry.evidence.is_none() && matches!(entry.status, CheckStatus::Refused { .. })
    ));
}

/// Review finding R3, second counterexample: a required check with a two-second
/// freshness of its own under a reader limit of 300 s. Three seconds after assembly that
/// check has expired, and the report with it.
#[test]
fn a_report_cannot_outlive_a_short_lived_required_check() {
    let (registry, clock) = registry();
    let mut inputs = passing_inputs(&registry);
    inputs.insert(
        check_id(4),
        CheckInput::Outcomes(vec![ProbeOutcome::host(
            check_id(4),
            Part::Primary,
            HostKind::Host,
            registry.now(),
            Duration::from_secs(2),
            configuration("host-a"),
            RunResult::Observed {
                observations: passing(4, Part::Primary, OsKind::Linux),
            },
        )
        .unwrap()]),
    );
    let report = BoundaryReport::assemble(
        linux_profile(&[RunProfile::Strict]),
        inputs.clone(),
        &linux_context(&registry),
    )
    .unwrap();
    assert!(
        report.allows_launch(),
        "positive control: inputs initially pass"
    );
    assert_eq!(
        report
            .entry(check_id(4))
            .unwrap()
            .evidence
            .map(|window| window
                .valid_until
                .saturating_duration_since(window.observed_at)),
        Some(Duration::from_secs(2))
    );
    // The report's own window is as short as its shortest check.
    assert_eq!(
        report.evidence_window().map(|window| window
            .valid_until
            .saturating_duration_since(window.observed_at)),
        Some(Duration::from_secs(2))
    );
    clock.advance(Duration::from_secs(2));
    assert_eq!(
        report.current_at(registry.now(), MAX_AGE, configuration("host-a")),
        Ok(()),
        "an age equal to the freshness is still within it"
    );
    clock.advance(Duration::from_secs(1));
    let rejudged = BoundaryReport::assemble(
        linux_profile(&[RunProfile::Strict]),
        inputs,
        &linux_context(&registry),
    )
    .unwrap();
    assert!(
        !rejudged.allows_launch(),
        "positive control: the required check expired"
    );
    assert_eq!(
        report.current_at(registry.now(), MAX_AGE, configuration("host-a")),
        Err(ObservationProblem::Stale {
            staleness: Staleness::TooOld {
                age: Duration::from_secs(3),
                limit: Duration::from_secs(2),
            }
        }),
        "the report must inherit the shorter check lifetime"
    );
}

/// A reader's own maximum age binds the cached report's evidence too, even when the
/// report was assembled under a longer one; and the report's own stamp still refuses
/// another configuration and another clock session first.
#[test]
fn a_cached_report_is_judged_at_the_readers_maximum_age_configuration_and_clock() {
    let (registry, clock) = registry();
    let inputs = passing_inputs(&registry);
    clock.advance(Duration::from_secs(10));
    let report = BoundaryReport::assemble(
        linux_profile(&[RunProfile::Strict]),
        inputs,
        &linux_context(&registry),
    )
    .unwrap();
    assert_eq!(
        report.current_at(
            registry.now(),
            Duration::from_secs(10),
            configuration("host-a")
        ),
        Ok(())
    );
    assert_eq!(
        report.current_at(
            registry.now(),
            Duration::from_secs(9),
            configuration("host-a")
        ),
        Err(ObservationProblem::Stale {
            staleness: Staleness::TooOld {
                age: Duration::from_secs(10),
                limit: Duration::from_secs(9),
            }
        }),
        "the evidence is ten seconds old for a reader accepting nine"
    );
    assert!(matches!(
        report.current_at(registry.now(), MAX_AGE, configuration("host-b")),
        Err(ObservationProblem::OtherConfiguration { .. })
    ));
    let restarted = ProbeRegistry::new(Arc::clone(&clock));
    assert_eq!(
        report.current_at(restarted.now(), MAX_AGE, configuration("host-a")),
        Err(ObservationProblem::Stale {
            staleness: Staleness::OtherClock
        })
    );
}
