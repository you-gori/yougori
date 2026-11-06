//! S01 acceptance on recorded answers: nothing here runs a query.

use std::sync::Arc;
use std::time::Duration;

use super::collect::{assemble, GPU_FIELDS, QUERY_MAX_OUTPUT, QUERY_TIMEOUT};
use super::*;
use crate::foundation::evidence::{
    Backend, BackendRelease, Capability, ComputePlatform, EvidenceRefusal, ObservationResult,
    OsKind, Remedy, Requirement, RuntimeSubject, SourceClass, Staleness, Subject, SupportDetail,
    UnknownReason, UnsupportedReason,
};
use crate::foundation::ids::{digest, Digest, ExecutionCategory, ManualClock, MonotonicTime};

const GUID: &str = "4C4C4544-0042-3510-8051-B4C04F4B3933";
const UUID_A: &str = "GPU-12345678-1234-1234-1234-123456789ABC";
const UUID_B: &str = "GPU-abcdefab-cdef-abcd-efab-cdefabcdefab";

fn row(uuid: &str, driver: &str, compute: &str, model: &str, used: u64) -> String {
    format!(
        "{uuid}, {driver}, {compute}, {model}, Disabled, 16376, {used}, {}",
        16376 - used
    )
}

fn ready() -> Option<CudaRuntimeFacts> {
    Some(CudaRuntimeFacts {
        supported: true,
        installed: true,
        running: true,
        update_available: false,
    })
}

fn at(seconds: u64) -> MonotonicTime {
    MonotonicTime::from_nanos(seconds * 1_000_000_000)
}

/// An inventory as a Windows host with `csv` from `nvidia-smi` would produce it.
fn inventory(
    started_at: MonotonicTime,
    csv: &str,
    cuda: Option<CudaRuntimeFacts>,
) -> HostInventory {
    let mut inventory = assemble(
        QueryOutcome::Output(format!("{GUID}\n")),
        QueryOutcome::Output("26200".into()),
        QueryOutcome::Output(csv.into()),
        cuda,
        started_at,
    );
    inventory.os = Some(OsFacts {
        kind: OsKind::Windows,
        architecture: "x86_64".into(),
        build: Some("26200".into()),
    });
    inventory
}

fn machine() -> Digest {
    machine_digest(GUID).unwrap()
}

fn device(uuid: &str) -> Digest {
    device_digest(uuid).unwrap()
}

fn gpu_subject(uuid: &str) -> Subject {
    Subject::GpuDevice(crate::foundation::evidence::GpuDeviceSubject {
        machine: machine(),
        device: device(uuid),
    })
}

fn runtime(instance: &str) -> RuntimeSubject {
    RuntimeSubject {
        category: ExecutionCategory::SharedKernelGpuRuntime,
        release: BackendRelease::new(Backend::Vllm, "0.31.0").unwrap(),
        instance: digest("yougori/test/runtime/v1", &[instance.as_bytes()]),
    }
}

struct Fixture {
    clock: Arc<ManualClock>,
    service: EvidenceService<ManualClock>,
}

impl Fixture {
    fn new() -> Self {
        let clock = Arc::new(ManualClock::new(at(100)));
        let service = EvidenceService::new(Arc::clone(&clock)).unwrap();
        Self { clock, service }
    }

    fn install(&mut self, csv: &str, cuda: Option<CudaRuntimeFacts>) -> InstallReport {
        let started = self.service.now();
        self.service.install(inventory(started, csv, cuda))
    }

    fn entry(&self, capability: Capability, subject: &Subject) -> StatusEntry {
        self.service
            .status()
            .entries
            .into_iter()
            .find(|entry| entry.capability == capability && entry.subject == *subject)
            .unwrap()
    }

    fn result(&self, capability: Capability, subject: &Subject) -> ObservationResult {
        self.entry(capability, subject)
            .evidence
            .unwrap()
            .result()
            .clone()
    }
}

#[test]
fn identities_are_the_ones_host_admission_names_its_subjects_by() {
    // model_runner/optimizer/capacity/probe.rs digests the lowercase MachineGuid and GPU
    // UUID under these domains; the ledger and the evidence must name the same subjects.
    assert_eq!(
        machine(),
        digest(
            "yougori/local-machine/v1",
            &[GUID.to_ascii_lowercase().as_bytes()]
        )
    );
    assert_eq!(
        machine_digest(&GUID.to_ascii_lowercase()).unwrap(),
        machine()
    );
    assert_eq!(
        device(UUID_A),
        digest(
            "yougori/nvidia-device/v1",
            &[UUID_A.to_ascii_lowercase().as_bytes()]
        )
    );
    for bad in ["", "not hex!", "a".repeat(129).as_str()] {
        assert_eq!(machine_digest(bad), Err(InventoryProblem::MachineIdentity));
    }
    for bad in [
        "GPU-short",
        "XPU-12345678-1234-1234-1234-123456789abc",
        "GPU-12345678-1234-1234-1234-12345678zzzz",
    ] {
        assert!(device_digest(bad).is_none(), "{bad}");
    }
}

#[test]
fn the_gpu_report_is_parsed_strictly() {
    let csv = format!(
        "{}\n{}\n",
        row(UUID_A, "592.01", "8.9", "WDDM", 1024),
        row(UUID_B, "592.01", "[N/A]", "[N/A]", 0)
    );
    let gpus = parse_gpus(&csv).unwrap();
    assert_eq!(gpus.len(), 2);
    assert_eq!(gpus[0].device, device(UUID_A));
    assert_eq!(gpus[0].compute_version(), Some((8, 9)));
    assert_eq!(gpus[0].driver_model, DriverModel::Wddm);
    assert_eq!(gpus[0].total_bytes.get(), 16376 * 1024 * 1024);
    assert_eq!(gpus[0].used_bytes, 1024 * 1024 * 1024);
    assert_eq!(gpus[1].compute_capability, None);
    assert_eq!(gpus[1].driver_model, DriverModel::NotReported);
    assert_eq!(parse_gpus("").unwrap(), Vec::new());

    let malformed = [
        format!("{UUID_A}, 592.01, 8.9, WDDM, Disabled, 16376, 0"),
        format!("{UUID_A}, 592.01, 8.9, WDDM, Disabled, 0, 0, 0"),
        format!("{UUID_A}, 592.01, 8.9, WDDM, Disabled, 16376, 20000, 0"),
        format!("{UUID_A}, 592.01, 8.9, WDDM, Sometimes, 16376, 0, 16376"),
        format!("{UUID_A}, 592.01, eight, WDDM, Disabled, 16376, 0, 16376"),
        format!("{UUID_A}, 592.01a, 8.9, WDDM, Disabled, 16376, 0, 16376"),
        format!("{UUID_A}, 592.01, 8.9, VGA, Disabled, 16376, 0, 16376"),
        "GPU-short, 592.01, 8.9, WDDM, Disabled, 16376, 0, 16376".to_owned(),
    ];
    for csv in &malformed {
        assert_eq!(
            parse_gpus(csv),
            Err(InventoryProblem::MalformedGpuRow { row: 1 }),
            "{csv}"
        );
    }
    let repeated = format!(
        "{}\n{}",
        row(UUID_A, "592.01", "8.9", "WDDM", 0),
        // The same GPU with its hex digits in the other case.
        row(&UUID_A.replace("ABC", "abc"), "592.01", "8.9", "WDDM", 0)
    );
    assert_eq!(parse_gpus(&repeated), Err(InventoryProblem::RepeatedGpu));
    let many: String = (0..=MAX_GPUS)
        .map(|index| {
            row(
                &format!("GPU-{index:08x}-1234-1234-1234-123456789abc"),
                "592.01",
                "8.9",
                "WDDM",
                0,
            ) + "\n"
        })
        .collect();
    assert_eq!(parse_gpus(&many), Err(InventoryProblem::TooManyGpus));
}

#[test]
fn registry_and_release_answers_are_read_as_tokens() {
    let output = "\r\nHKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Cryptography\r\n    MachineGuid    REG_SZ    4c4c4544-0042\r\n\r\n";
    assert_eq!(
        parse_registry_value(output, "MachineGuid"),
        Some("4c4c4544-0042")
    );
    assert_eq!(parse_registry_value(output, "CurrentBuildNumber"), None);
    assert_eq!(
        parse_os_release(" 6.8.0-45-generic\n").unwrap(),
        "6.8.0-45-generic"
    );
    for bad in ["", "26200; rm", "9".repeat(65).as_str()] {
        assert_eq!(parse_os_release(bad), Err(InventoryProblem::OsBuild));
    }
}

#[test]
fn query_problems_become_explicit_inventory_states() {
    let inventory = assemble(
        QueryOutcome::Problem(InventoryProblem::TimedOut),
        QueryOutcome::Problem(InventoryProblem::QueryFailed),
        QueryOutcome::Problem(InventoryProblem::ToolMissing),
        None,
        at(1),
    );
    assert_eq!(
        inventory.machine,
        MachineIdentity::Unavailable {
            problem: InventoryProblem::MachineIdentity
        }
    );
    assert_eq!(inventory.os.as_ref().and_then(|os| os.build.clone()), None);
    assert_eq!(
        inventory.gpus,
        GpuInventory::Unavailable {
            problem: InventoryProblem::ToolMissing
        }
    );
    let malformed = assemble(
        QueryOutcome::Output(GUID.into()),
        QueryOutcome::Output("26200".into()),
        QueryOutcome::Output("garbage".into()),
        None,
        at(1),
    );
    assert_eq!(
        malformed.gpus,
        GpuInventory::Unavailable {
            problem: InventoryProblem::MalformedGpuRow { row: 1 }
        }
    );
}

#[test]
fn the_dry_run_plan_names_bounded_direct_queries_and_runs_nothing() {
    let plan = plan();
    let queries: Vec<Query> = plan.iter().map(|query| query.query).collect();
    assert_eq!(
        queries,
        [Query::MachineIdentity, Query::OsBuild, Query::Gpus]
    );
    for query in &plan {
        assert_eq!(query.timeout_ms, 5_000);
        assert_eq!(query.max_output_bytes, QUERY_MAX_OUTPUT);
        if let Some(reads) = &query.reads {
            let program = reads.to_ascii_lowercase();
            for shell in ["cmd.exe", "powershell", "/bin/sh", "bash"] {
                assert!(!program.contains(shell), "{reads} is a shell");
            }
        }
    }
    assert_eq!(QUERY_TIMEOUT, Duration::from_secs(5));
    if cfg!(windows) {
        let gpus = &plan[2];
        assert!(gpus
            .reads
            .as_deref()
            .unwrap()
            .to_ascii_lowercase()
            .ends_with("nvidia-smi.exe"));
        assert_eq!(gpus.arguments[0], format!("--query-gpu={GPU_FIELDS}"));
        assert!(plan[0]
            .reads
            .as_deref()
            .unwrap()
            .to_ascii_lowercase()
            .ends_with("reg.exe"));
    }
}

#[test]
fn every_capability_is_either_observed_here_or_assigned_to_an_open_task() {
    let service = Fixture::new().service;
    for capability in Capability::ALL {
        let assigned = UNCOVERED.iter().any(|entry| entry.capability == capability);
        assert!(
            service.registry().is_registered(capability) || assigned,
            "{capability} has no producer and no open task"
        );
    }
    // The provider API adapters are registered beside the host's.
    for capability in [
        Capability::ProviderContainer,
        Capability::RuntimeCategory,
        Capability::ComputePlatform,
    ] {
        assert!(service
            .registry()
            .sources(capability)
            .contains(&SourceClass::ProviderApi));
    }
    for entry in UNCOVERED {
        assert!(!entry.open_task.is_empty() && !entry.reason.is_empty());
    }
    let status = Fixture::new().service.status();
    assert!(status.entries.is_empty());
    assert_eq!(status.inventory, None);
    assert_eq!(status.uncovered, UNCOVERED);
}

#[test]
fn each_gpu_is_observed_by_the_host_with_its_free_and_total_memory() {
    let mut fixture = Fixture::new();
    let report = fixture.install(
        &format!(
            "{}\n{}",
            row(UUID_A, "592.01", "8.9", "WDDM", 1024),
            row(UUID_B, "592.01", "8.6", "WDDM", 0)
        ),
        ready(),
    );
    assert_eq!(report.observed, 2);
    assert!(report.refused.is_empty());
    let entry = fixture.entry(Capability::GpuFreeMemory, &gpu_subject(UUID_A));
    assert_eq!(entry.verdict, Verdict::Satisfied);
    let evidence = entry.evidence.unwrap();
    assert_eq!(evidence.source(), SourceClass::HostProbe);
    assert_eq!(
        evidence.result(),
        &ObservationResult::Supported {
            detail: SupportDetail::GpuMemory {
                free_bytes: (16376 - 1024) * 1024 * 1024,
                total_bytes: std::num::NonZeroU64::new(16376 * 1024 * 1024).unwrap(),
            }
        }
    );
    assert_eq!(evidence.fresh_for(), GPU_MEMORY_FRESH_FOR);
}

#[test]
fn evidence_ages_out_and_an_old_inventory_reads_not_tested() {
    let mut fixture = Fixture::new();
    fixture.install(&row(UUID_A, "592.01", "8.9", "WDDM", 0), ready());
    let subject = gpu_subject(UUID_A);
    fixture.clock.advance(Duration::from_secs(6));
    assert!(matches!(
        fixture.entry(Capability::GpuFreeMemory, &subject).verdict,
        Verdict::Refused {
            refusal: EvidenceRefusal::Stale {
                staleness: Staleness::TooOld { .. },
                ..
            },
            remedy: Remedy::RunCheckAgain,
        }
    ));
    // Observing again from the same, now old, inventory never renews it.
    fixture.service.refresh();
    assert_eq!(
        fixture.result(Capability::GpuFreeMemory, &subject),
        ObservationResult::Unknown {
            reason: UnknownReason::NotTested
        }
    );
    assert!(matches!(
        fixture.entry(Capability::GpuFreeMemory, &subject).verdict,
        Verdict::Refused {
            remedy: Remedy::RunCheck,
            ..
        }
    ));
    // A new collection renews it.
    fixture.install(&row(UUID_A, "592.01", "8.9", "WDDM", 0), ready());
    assert_eq!(
        fixture.entry(Capability::GpuFreeMemory, &subject).verdict,
        Verdict::Satisfied
    );
}

#[test]
fn a_changed_configuration_invalidates_the_evidence_observed_under_the_old_one() {
    let mut fixture = Fixture::new();
    fixture.install(&row(UUID_A, "592.01", "8.9", "WDDM", 0), ready());
    let subject = gpu_subject(UUID_A);
    let old = fixture
        .service
        .requirement(Capability::GpuFreeMemory, &subject)
        .unwrap();
    // The driver is updated; memory use alone would not count as a change.
    let report = fixture.install(&row(UUID_A, "596.36", "8.9", "WDDM", 512), ready());
    assert_eq!(report.changed_configurations, 1);
    assert_eq!(report.dropped_evidence, 1);
    assert!(matches!(
        fixture.service.evaluate(&old),
        Err(EvidenceRefusal::FingerprintChanged { .. })
    ));
    let current = fixture
        .service
        .requirement(Capability::GpuFreeMemory, &subject)
        .unwrap();
    assert_ne!(current.configuration, old.configuration);
    assert!(fixture.service.evaluate(&current).is_ok());

    let unchanged = fixture.install(&row(UUID_A, "596.36", "8.9", "WDDM", 4096), ready());
    assert_eq!(unchanged.changed_configurations, 0);
    assert_eq!(unchanged.dropped_evidence, 0);
}

#[test]
fn a_removed_gpu_loses_its_evidence_and_a_failed_query_is_explicit() {
    let mut fixture = Fixture::new();
    fixture.install(
        &format!(
            "{}\n{}",
            row(UUID_A, "592.01", "8.9", "WDDM", 0),
            row(UUID_B, "592.01", "8.9", "WDDM", 0)
        ),
        ready(),
    );
    let report = fixture.install(&row(UUID_A, "592.01", "8.9", "WDDM", 0), ready());
    assert_eq!(report.removed_subjects, 1);
    assert!(fixture
        .service
        .registry()
        .latest(Capability::GpuFreeMemory, &gpu_subject(UUID_B))
        .is_none());

    // The query fails: the GPU stays listed, with an explicit result.
    let started = fixture.service.now();
    let mut failed = inventory(started, "", ready());
    failed.gpus = GpuInventory::Unavailable {
        problem: InventoryProblem::TimedOut,
    };
    fixture.service.install(failed);
    assert_eq!(
        fixture.result(Capability::GpuFreeMemory, &gpu_subject(UUID_A)),
        ObservationResult::Unknown {
            reason: UnknownReason::Inconclusive
        }
    );
    let started = fixture.service.now();
    let mut missing = inventory(started, "", ready());
    missing.gpus = GpuInventory::Unavailable {
        problem: InventoryProblem::ToolMissing,
    };
    fixture.service.install(missing);
    assert_eq!(
        fixture.result(Capability::GpuFreeMemory, &gpu_subject(UUID_A)),
        ObservationResult::Unsupported {
            reason: UnsupportedReason::FeatureAbsent
        }
    );
}

#[test]
fn another_machine_or_an_older_collection_never_takes_over() {
    let mut fixture = Fixture::new();
    let early = fixture.service.now();
    fixture.clock.advance(Duration::from_secs(1));
    fixture.install(&row(UUID_A, "592.01", "8.9", "WDDM", 0), ready());
    let late = fixture.service.install(inventory(
        early,
        &row(UUID_B, "592.01", "8.9", "WDDM", 0),
        ready(),
    ));
    assert!(late.superseded);
    assert!(fixture
        .service
        .registry()
        .latest(Capability::GpuFreeMemory, &gpu_subject(UUID_A))
        .is_some());

    let started = fixture.service.now();
    let mut moved = inventory(started, &row(UUID_A, "592.01", "8.9", "WDDM", 0), ready());
    moved.machine = MachineIdentity::Known {
        machine: machine_digest("00000000-0000-0000-0000-000000000001").unwrap(),
    };
    let report = fixture.service.install(moved);
    assert_eq!(report.removed_subjects, 1);
    assert!(fixture
        .service
        .registry()
        .latest(Capability::GpuFreeMemory, &gpu_subject(UUID_A))
        .is_none());
}

#[test]
fn a_bound_local_runtime_is_observed_and_unbinding_drops_it() {
    let mut fixture = Fixture::new();
    fixture.install(&row(UUID_A, "592.01", "8.9", "WDDM", 0), ready());
    let runtime = runtime("one");
    let subject = Subject::Runtime(runtime.clone());
    let report = fixture
        .service
        .bind_runtime(RuntimeBinding::new(runtime.clone(), vec![device(UUID_A)]).unwrap());
    assert!(report.refused.is_empty(), "{:?}", report.refused);
    assert_eq!(
        fixture.result(Capability::ComputePlatform, &subject),
        ObservationResult::Supported {
            detail: SupportDetail::ComputePlatform {
                platform: ComputePlatform::Cuda
            }
        }
    );
    assert_eq!(
        fixture.result(Capability::RuntimeCategory, &subject),
        ObservationResult::Supported {
            detail: SupportDetail::RuntimeCategory {
                category: ExecutionCategory::SharedKernelGpuRuntime
            }
        }
    );
    assert!(matches!(
        fixture.result(Capability::PeerTopology, &subject),
        ObservationResult::Supported {
            detail: SupportDetail::PeerTopology { ref paths, .. }
        } if paths.is_empty()
    ));
    for capability in [
        Capability::ComputePlatform,
        Capability::RuntimeCategory,
        Capability::PeerTopology,
    ] {
        assert_eq!(
            fixture.entry(capability, &subject).verdict,
            Verdict::Satisfied
        );
    }

    let report = fixture.service.unbind_runtime(&runtime);
    assert_eq!(report.removed_subjects, 1);
    assert_eq!(report.dropped_evidence, 3);
    assert!(fixture
        .service
        .registry()
        .latest(Capability::ComputePlatform, &subject)
        .is_none());
}

#[test]
fn a_sleep_cycle_the_engine_saw_is_sleep_mode_weight_discarding_of_that_bound_runtime() {
    const GIB: u64 = 1 << 30;
    let mut fixture = Fixture::new();
    fixture.install(&row(UUID_A, "592.01", "8.9", "WDDM", 0), ready());
    let runtime = runtime("one");
    let subject = Subject::Runtime(runtime.clone());
    let cycle = |before: u64, parked: u64, awake: u64| SleepCycle {
        used_before_bytes: before,
        used_parked_bytes: parked,
        used_awake_bytes: awake,
        engine_wake_ms: 812.5,
        weight_reload_ms: 640.25,
        slept_ms: 30_000,
        recorded_at: at(0),
    };
    // A runtime that is not bound records nothing.
    assert!(fixture
        .service
        .record_sleep_cycle(&runtime, cycle(22 * GIB, GIB, 22 * GIB))
        .is_err());
    fixture
        .service
        .bind_runtime(RuntimeBinding::new(runtime.clone(), vec![device(UUID_A)]).unwrap());
    // Bound without a cycle: the capability is not observed for it.
    assert!(fixture
        .service
        .status()
        .entries
        .iter()
        .all(|entry| entry.capability != Capability::SleepWeightDiscard));
    let report = fixture
        .service
        .record_sleep_cycle(&runtime, cycle(22 * GIB, GIB, 22 * GIB))
        .unwrap();
    assert!(report.refused.is_empty(), "{:?}", report.refused);
    assert_eq!(
        fixture.result(Capability::SleepWeightDiscard, &subject),
        ObservationResult::Supported {
            detail: SupportDetail::BackendMode {
                release: runtime.release.clone()
            }
        }
    );
    let entry = fixture.entry(Capability::SleepWeightDiscard, &subject);
    assert_eq!(entry.verdict, Verdict::Satisfied);
    assert_eq!(
        entry.evidence.as_ref().unwrap().source(),
        SourceClass::HostProbe
    );
    let cycles = fixture.service.sleep_cycles();
    assert_eq!(cycles.len(), 1);
    assert_eq!(cycles[0].0, runtime);
    assert_eq!(cycles[0].1.returned_and_retaken(), (21 * GIB, 21 * GIB));
    // Still evidence an hour later: what the release did does not change while it runs.
    fixture.clock.advance(Duration::from_secs(3600));
    fixture.service.refresh();
    assert_eq!(
        fixture
            .entry(Capability::SleepWeightDiscard, &subject)
            .verdict,
        Verdict::Satisfied
    );
    // A park that returned almost nothing kept the weights: unsupported.
    fixture
        .service
        .record_sleep_cycle(&runtime, cycle(22 * GIB, 22 * GIB - (64 << 20), 22 * GIB))
        .unwrap();
    assert_eq!(
        fixture.result(Capability::SleepWeightDiscard, &subject),
        ObservationResult::Unsupported {
            reason: UnsupportedReason::FeatureAbsent
        }
    );
    // A wake that took nothing again is inconclusive.
    fixture
        .service
        .record_sleep_cycle(&runtime, cycle(22 * GIB, GIB, GIB))
        .unwrap();
    assert_eq!(
        fixture.result(Capability::SleepWeightDiscard, &subject),
        ObservationResult::Unknown {
            reason: UnknownReason::Inconclusive
        }
    );
    // Unbinding drops the cycle and its evidence with the runtime.
    fixture.service.unbind_runtime(&runtime);
    assert!(fixture.service.sleep_cycles().is_empty());
    assert!(fixture
        .service
        .registry()
        .latest(Capability::SleepWeightDiscard, &subject)
        .is_none());
}

#[test]
fn a_runtime_without_a_ready_cuda_runtime_or_a_capable_gpu_is_refused_explicitly() {
    let cases = [
        (
            Some(CudaRuntimeFacts {
                installed: false,
                ..ready().unwrap()
            }),
            row(UUID_A, "592.01", "8.9", "WDDM", 0),
            ObservationResult::Unsupported {
                reason: UnsupportedReason::FeatureAbsent,
            },
        ),
        (
            Some(CudaRuntimeFacts {
                update_available: true,
                ..ready().unwrap()
            }),
            row(UUID_A, "592.01", "8.9", "WDDM", 0),
            ObservationResult::Unknown {
                reason: UnknownReason::Inconclusive,
            },
        ),
        (
            None,
            row(UUID_A, "592.01", "8.9", "WDDM", 0),
            ObservationResult::Unknown {
                reason: UnknownReason::NotTested,
            },
        ),
        (
            ready(),
            row(UUID_A, "592.01", "8.9", "TCC", 0),
            ObservationResult::Unsupported {
                reason: UnsupportedReason::FeatureAbsent,
            },
        ),
        (
            ready(),
            row(UUID_A, "592.01", "5.2", "WDDM", 0),
            ObservationResult::Unsupported {
                reason: UnsupportedReason::FeatureAbsent,
            },
        ),
        (
            ready(),
            row(UUID_B, "592.01", "8.9", "WDDM", 0),
            ObservationResult::Unknown {
                reason: UnknownReason::Unreachable,
            },
        ),
    ];
    for (cuda, csv, expected) in cases {
        let mut fixture = Fixture::new();
        fixture.install(&csv, cuda);
        let runtime = runtime("one");
        fixture
            .service
            .bind_runtime(RuntimeBinding::new(runtime.clone(), vec![device(UUID_A)]).unwrap());
        assert_eq!(
            fixture.result(Capability::ComputePlatform, &Subject::Runtime(runtime)),
            expected,
            "{csv} {cuda:?}"
        );
    }

    let mut fixture = Fixture::new();
    fixture.install(
        &row(UUID_A, "592.01", "8.9", "WDDM", 0),
        Some(CudaRuntimeFacts {
            running: false,
            ..ready().unwrap()
        }),
    );
    let runtime = runtime("one");
    fixture
        .service
        .bind_runtime(RuntimeBinding::new(runtime.clone(), vec![device(UUID_A)]).unwrap());
    assert_eq!(
        fixture.result(Capability::RuntimeCategory, &Subject::Runtime(runtime)),
        ObservationResult::Unknown {
            reason: UnknownReason::Unreachable
        }
    );
}

#[test]
fn peer_topology_is_never_assumed_for_several_gpus() {
    let mut fixture = Fixture::new();
    fixture.install(
        &format!(
            "{}\n{}",
            row(UUID_A, "592.01", "8.9", "WDDM", 0),
            row(UUID_B, "592.01", "8.9", "WDDM", 0)
        ),
        ready(),
    );
    let pair = runtime("pair");
    fixture.service.bind_runtime(
        RuntimeBinding::new(pair.clone(), vec![device(UUID_A), device(UUID_B)]).unwrap(),
    );
    assert_eq!(
        fixture.result(Capability::PeerTopology, &Subject::Runtime(pair)),
        ObservationResult::Unknown {
            reason: UnknownReason::NotTested
        }
    );
    let cpu = runtime("cpu");
    fixture
        .service
        .bind_runtime(RuntimeBinding::new(cpu.clone(), Vec::new()).unwrap());
    assert_eq!(
        fixture.result(Capability::ComputePlatform, &Subject::Runtime(cpu.clone())),
        ObservationResult::Supported {
            detail: SupportDetail::ComputePlatform {
                platform: ComputePlatform::Cpu
            }
        }
    );
    assert_eq!(
        fixture.result(Capability::PeerTopology, &Subject::Runtime(cpu)),
        ObservationResult::Unsupported {
            reason: UnsupportedReason::FeatureAbsent
        }
    );
}

#[test]
fn only_local_runtimes_bind_and_each_gpu_once() {
    let mut vm = runtime("vm");
    vm.category = ExecutionCategory::VmSandbox;
    assert_eq!(
        RuntimeBinding::new(vm, Vec::new()),
        Err(BindingError::NotLocal {
            category: ExecutionCategory::VmSandbox
        })
    );
    assert_eq!(
        RuntimeBinding::new(runtime("one"), vec![device(UUID_A), device(UUID_A)]),
        Err(BindingError::RepeatedDevice)
    );
    let many = (0..=MAX_GPUS)
        .map(|index| digest("yougori/test/gpu/v1", &[index.to_le_bytes().as_slice()]))
        .collect();
    assert_eq!(
        RuntimeBinding::new(runtime("one"), many),
        Err(BindingError::TooManyDevices)
    );
}

#[test]
fn a_runtime_bound_before_any_collection_reads_not_collected() {
    let mut fixture = Fixture::new();
    let runtime = runtime("early");
    fixture
        .service
        .bind_runtime(RuntimeBinding::new(runtime.clone(), Vec::new()).unwrap());
    let entry = fixture.entry(Capability::ComputePlatform, &Subject::Runtime(runtime));
    assert_eq!(entry.verdict, Verdict::NotCollected);
    assert_eq!(
        entry.evidence.unwrap().result(),
        &ObservationResult::Unknown {
            reason: UnknownReason::NotTested
        }
    );
}

#[test]
fn the_status_is_json_without_raw_identifiers() {
    let mut fixture = Fixture::new();
    fixture.install(&row(UUID_A, "592.01", "8.9", "WDDM", 0), ready());
    fixture
        .service
        .bind_runtime(RuntimeBinding::new(runtime("one"), vec![device(UUID_A)]).unwrap());
    let text = serde_json::to_string(&fixture.service.status()).unwrap();
    for raw in [GUID, UUID_A] {
        assert!(!text
            .to_ascii_lowercase()
            .contains(&raw.to_ascii_lowercase()));
    }
    let value: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(value["entries"].as_array().unwrap().len(), 4);
    assert!(value["uncovered"].as_array().unwrap().len() >= 10);
}

#[test]
fn a_host_requirement_is_met_only_by_the_hosts_own_fresh_observation() {
    let mut fixture = Fixture::new();
    fixture.install(&row(UUID_A, "592.01", "8.9", "WDDM", 0), ready());
    let subject = gpu_subject(UUID_A);
    let requirement = fixture
        .service
        .requirement(Capability::GpuFreeMemory, &subject)
        .unwrap();
    assert_eq!(requirement.minimum_source, SourceClass::HostProbe);
    assert_eq!(requirement.max_age, GPU_MEMORY_FRESH_FOR);
    let elsewhere = Requirement::host_only(
        Capability::GpuFreeMemory,
        gpu_subject(UUID_B),
        GPU_MEMORY_FRESH_FOR,
        requirement.configuration,
    );
    assert!(matches!(
        fixture.service.evaluate(&elsewhere),
        Err(EvidenceRefusal::Missing { .. })
    ));
}

#[test]
fn provider_reports_are_observed_through_the_same_registry_and_a_changed_report_drops_its_evidence()
{
    use crate::foundation::evidence::{ProviderKind, ProviderSubject};
    use crate::sandbox_contract::provider_evidence::{ProviderReport, RecordOutcome};
    use crate::sandbox_contract::remote::{
        OfferingKind, OfferingName, ProviderInstance, RegionName,
    };

    let mut fixture = Fixture::new();
    let instance = digest("yougori/test/provider-instance/v1", &[b"pod-1".as_slice()]);
    let report = ProviderReport::instance_only(ProviderInstance {
        provider: ProviderKind::RunPod,
        region: RegionName::new("us-east-1").unwrap(),
        offering: OfferingName::new("gpu-1x").unwrap(),
        kind: OfferingKind::ProviderContainer,
        instance,
    });
    let subject = Subject::Provider(ProviderSubject {
        provider: ProviderKind::RunPod,
        resource: instance,
    });
    // No report yet: neither the host nor the provider adapters know the subject.
    assert!(fixture
        .service
        .requirement(Capability::ProviderContainer, &subject)
        .is_none());

    let started = fixture.service.now();
    let outcome = fixture
        .service
        .record_provider_report(report.clone(), started)
        .unwrap();
    assert!(matches!(outcome, RecordOutcome::New { .. }));
    let requirement = fixture
        .service
        .requirement(Capability::ProviderContainer, &subject)
        .unwrap();
    assert_eq!(requirement.minimum_source, SourceClass::ProviderApi);
    fixture
        .service
        .observe(Capability::ProviderContainer, &subject)
        .unwrap();
    assert!(fixture
        .service
        .registry()
        .latest(Capability::ProviderContainer, &subject)
        .is_some());

    // The provider now reports gVisor: the configuration changes and the old evidence goes.
    fixture.clock.advance(Duration::from_secs(1));
    let changed = ProviderReport {
        gvisor: Some(true),
        ..report
    };
    let started = fixture.service.now();
    let outcome = fixture
        .service
        .record_provider_report(changed, started)
        .unwrap();
    assert!(matches!(outcome, RecordOutcome::Changed { .. }));
    assert!(fixture
        .service
        .registry()
        .latest(Capability::ProviderContainer, &subject)
        .is_none());

    // Forgetting the instance drops what was observed under its report.
    fixture
        .service
        .observe(Capability::ProviderContainer, &subject)
        .unwrap();
    assert_eq!(fixture.service.forget_provider_report(&instance), 1);
    assert!(fixture
        .service
        .requirement(Capability::ProviderContainer, &subject)
        .is_none());
}
