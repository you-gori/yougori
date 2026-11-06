//! The model reclaimers on fakes and the real CORE-03 ledger (GPU-W05), and over real
//! components where they can run without a live workload: the ladder's rules in `ladder`,
//! the sources over the pinned host tier and the placement slot in `components`, and the
//! GPU tier's finished-session KV and idle weights in `gpu`.

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use super::*;
use crate::foundation::evidence::{HostSubject, SourceClass};
use crate::foundation::ids::{
    digest, Clock, ExecutionCategory, ExecutionId, GpuDeviceKey, ManualClock, MonotonicTime,
    OperationId, TenantId, TrustScope,
};
use crate::foundation::ledger::{
    Admission, Amounts, CapacityDeclaration, CostPurpose, DeclineReason, DeviceId, HostResource,
    LadderReport, Ledger, LedgerConfig, LedgerError, LedgerEvent, Priority, Provenance,
    QueueLimits, ReclaimAdmission, ReclaimLadder, ReclaimStep, Requester, ReservationId,
    ReservationRequest, ReservationState, ResourceKey, StepOutcome,
};
use crate::model_memory::residency::host::{HostScope, HostScopeKind, ScopeOccupancy};
use crate::model_memory::residency::Capacity;
use crate::model_memory::tiers::{
    Consumer, LedgerCharge, MemlockLimit, PinnedHostTier, PinnedLimits, WslLimit,
};

const MIB: u64 = 1 << 20;
const GIB: u64 = 1 << 30;
const RAM: ResourceKey = ResourceKey::Host(HostResource::Ram);
const PINNED: ResourceKey = ResourceKey::Host(HostResource::PinnedRam);

fn machine() -> crate::foundation::ids::Digest {
    digest("yougori/test/machine/v1", &[b"workstation"])
}

fn gpu() -> ResourceKey {
    ResourceKey::Vram(DeviceId::from(GpuDeviceKey {
        machine: machine(),
        device: digest("yougori/test/gpu/v1", &[&[0]]),
    }))
}

fn tenant() -> TenantId {
    TenantId::new("alpha").unwrap()
}

fn provenance(requester: Requester, name: &str) -> Provenance {
    Provenance {
        requester,
        execution: ExecutionId::new(format!("exe-{name}")).unwrap(),
        operation: OperationId::new(format!("op-{name}")).unwrap(),
        tenant: tenant(),
        purpose: CostPurpose::Compute,
        retry_number: 0,
    }
}

fn declare<C: Clock>(ledger: &mut Ledger<C>, resource: ResourceKey, total: u64) {
    ledger
        .declare_capacity(
            resource,
            CapacityDeclaration {
                total,
                supervisor_reserve: 0,
                unmanaged_in_use: 0,
                source: SourceClass::HostProbe,
            },
        )
        .unwrap();
    ledger
        .set_tenant_budget(tenant(), resource, u64::MAX)
        .unwrap();
}

fn config() -> LedgerConfig {
    LedgerConfig {
        queue: QueueLimits {
            max_entries: 8,
            max_entries_per_tenant: 8,
            max_wait: Duration::from_secs(60),
        },
        grant_ttl: Duration::from_secs(60),
        unmanaged_usage_max_age: Duration::from_secs(1 << 40),
    }
}

fn start() -> Arc<ManualClock> {
    Arc::new(ManualClock::new(MonotonicTime::from_nanos(1_000)))
}

/// A host on `clock` with `vram` bytes on GPU 0 and `ram` bytes of host RAM, all free.
fn ledger_on(clock: Arc<ManualClock>, vram: u64, ram: u64) -> Ledger<Arc<ManualClock>> {
    let mut ledger = Ledger::new(clock, HostSubject { machine: machine() }, config());
    declare(&mut ledger, gpu(), vram);
    declare(&mut ledger, RAM, ram);
    ledger
}

fn ledger(vram: u64, ram: u64) -> Ledger<Arc<ManualClock>> {
    ledger_on(start(), vram, ram)
}

/// A reservation of `amounts` that `requester` filed for `name`, created when `in_use`.
fn hold<C: Clock>(
    ledger: &mut Ledger<C>,
    requester: Requester,
    name: &str,
    amounts: Amounts,
    in_use: bool,
) -> ReservationId {
    let request =
        ReservationRequest::new(provenance(requester, name), Priority::Foreground, amounts);
    let Ok(Admission::Granted(reservation)) = ledger.reserve(request) else {
        panic!("{name} is granted");
    };
    if in_use {
        ledger.begin_create(reservation).unwrap();
    }
    reservation
}

fn vram(bytes: u64) -> Amounts {
    Amounts::new().with(gpu(), bytes)
}

/// A foreground model load of `bytes` of GPU 0 that does not wait.
fn load(name: &str, bytes: u64) -> ReservationRequest {
    ReservationRequest::new(
        provenance(Requester::ModelPlacement, name),
        Priority::Foreground,
        vram(bytes),
    )
}

fn state<C: Clock>(ledger: &Ledger<C>, reservation: ReservationId) -> Option<ReservationState> {
    ledger.reservation(reservation).map(|record| record.state())
}

/// One unit of fake work.
#[derive(Clone, Debug)]
struct FakeWork {
    name: String,
    reservations: Vec<ReservationId>,
    hold: Hold,
    rank: f64,
}

fn work(name: &str, reservations: &[ReservationId], hold: Hold, rank: f64) -> FakeWork {
    FakeWork {
        name: name.to_string(),
        reservations: reservations.to_vec(),
        hold,
        rank,
    }
}

/// A fake component of one owner: reports its work as told, records what it stops,
/// refuses to stop what it is told to, and fails the test on stopping foreign or
/// stopped work.
struct Fake {
    owner: Requester,
    works: Vec<FakeWork>,
    stopped: Vec<String>,
    refuse: BTreeSet<String>,
}

impl Fake {
    fn new(owner: Requester, works: Vec<FakeWork>) -> Self {
        Self {
            owner,
            works,
            stopped: Vec::new(),
            refuse: BTreeSet::new(),
        }
    }
}

impl WorkSource for Fake {
    type Work = String;

    fn owner(&self) -> Requester {
        self.owner
    }

    fn survey(&mut self) -> Vec<Candidate<String>> {
        self.works
            .iter()
            .filter(|work| !self.stopped.contains(&work.name))
            .map(|work| Candidate {
                work: work.name.clone(),
                reservations: work.reservations.clone(),
                hold: work.hold,
                rank: work.rank,
            })
            .collect()
    }

    fn stop(&mut self, work: &String) -> Result<(), StopError> {
        assert!(
            self.works.iter().any(|known| known.name == *work),
            "{work} is not work of {:?}",
            self.owner
        );
        assert!(!self.stopped.contains(work), "{work} was stopped twice");
        if self.refuse.contains(work) {
            return Err(StopError::Refused {
                reason: format!("{work} cannot stop now"),
            });
        }
        self.stopped.push(work.clone());
        Ok(())
    }
}

impl SpeculationSource for Fake {}
impl ScratchSource for Fake {}
impl CacheSource for Fake {}
impl ParkingSource for Fake {}

/// The four fake components, one per rung.
struct Fakes {
    speculation: Fake,
    scratch: Fake,
    caches: Fake,
    parking: Fake,
}

impl Fakes {
    fn new() -> Self {
        Self {
            speculation: Fake::new(Requester::Transfer, Vec::new()),
            scratch: Fake::new(Requester::ModelPlacement, Vec::new()),
            caches: Fake::new(Requester::ModelPlacement, Vec::new()),
            parking: Fake::new(Requester::Coordination, Vec::new()),
        }
    }

    fn stopped(&self) -> BTreeSet<String> {
        [
            &self.speculation,
            &self.scratch,
            &self.caches,
            &self.parking,
        ]
        .into_iter()
        .flat_map(|fake| fake.stopped.iter().cloned())
        .collect()
    }
}

/// The four model steps.
struct Steps {
    speculation: CancelSpeculation<String>,
    scratch: ReclaimUnusedScratch<String>,
    caches: DropLowValueCaches<String>,
    parking: ParkEligibleIdleModels<String>,
}

impl Steps {
    fn for_fakes(fakes: &Fakes) -> Self {
        Self {
            speculation: CancelSpeculation::for_source(&fakes.speculation),
            scratch: ReclaimUnusedScratch::for_source(&fakes.scratch),
            caches: DropLowValueCaches::for_source(&fakes.caches),
            parking: ParkEligibleIdleModels::for_source(&fakes.parking),
        }
    }
}

/// What one admission did: the ledger's answer and each step's settlement, in rung
/// order.
struct Round {
    admission: ReclaimAdmission,
    registered: Vec<(ReclaimStep, Requester)>,
    settlements: [Settlement; 4],
}

/// Prepares every step, lends them to the ledger for `request` in the plan's order
/// (registered here in reverse), then settles them.
fn admit<C: Clock>(
    ledger: &mut Ledger<C>,
    request: ReservationRequest,
    steps: &mut Steps,
    fakes: &mut Fakes,
) -> Round {
    steps.speculation.prepare(&mut fakes.speculation).unwrap();
    steps.scratch.prepare(&mut fakes.scratch).unwrap();
    steps.caches.prepare(&mut fakes.caches).unwrap();
    steps.parking.prepare(&mut fakes.parking).unwrap();
    let (admission, registered) = {
        let mut ladder = ReclaimLadder::new();
        let registered = register_model_reclaimers(
            &mut ladder,
            [
                &mut steps.parking as &mut dyn ModelReclaimer,
                &mut steps.caches,
                &mut steps.scratch,
                &mut steps.speculation,
            ],
        );
        (ledger.reserve_reclaiming(request, &mut ladder), registered)
    };
    let report = &admission.report;
    let settlements = [
        steps
            .speculation
            .settle(report, &mut fakes.speculation)
            .unwrap(),
        steps.scratch.settle(report, &mut fakes.scratch).unwrap(),
        steps.caches.settle(report, &mut fakes.caches).unwrap(),
        steps.parking.settle(report, &mut fakes.parking).unwrap(),
    ];
    Round {
        admission,
        registered,
        settlements,
    }
}

/// What the ledger did at one rung, as (returned, releasing, refused).
fn released(
    report: &LadderReport,
    step: ReclaimStep,
) -> (Vec<ReservationId>, Vec<ReservationId>, usize) {
    let outcome = report
        .steps()
        .iter()
        .find(|report| report.step == step)
        .map(|report| report.outcome.clone());
    match outcome {
        Some(StepOutcome::Released {
            returned,
            releasing,
            refused,
        }) => (
            returned
                .iter()
                .map(|returned| returned.reservation)
                .collect(),
            releasing,
            refused.len(),
        ),
        other => panic!("{step} gave nothing up: {other:?}"),
    }
}

fn names(stopped: &[StoppedWork]) -> Vec<&str> {
    stopped
        .iter()
        .map(|stopped| stopped.work.as_str())
        .collect()
}

mod caches;
mod components;
mod gpu;
mod ladder;
