//! The GPU-tier steps over a real GPU tier, catalog, local storage tier and the real
//! ledger: the KV of finished sessions goes on rung 3 before any cache of value, weights
//! nothing references are parked clean on rung 4 only when a verified copy rebuilds them,
//! nothing a live session, a reference, its owner, a shared extent or a transition peak
//! holds is given up, what could not be freed is reported, and a release closes only on
//! an observation with authority.

use std::fmt;

use tempfile::TempDir;

use super::caches::{alice, forecast, import, open_catalog, pool, STORAGE};
use super::components::pinned_tier;
use super::*;
use crate::foundation::catalog::{Catalog, ObjectRole, ObjectStatus};
use crate::foundation::ledger::{ExtentKey, ReleaseOutcome, ShareRelease};
use crate::model_memory::reclaim::gpu::ledger_hold;
use crate::model_memory::tiers::{
    AllocationHandle, CopyState, GpuRefusal, GpuTier, LocalStorageTier, MutableState, ObjectRef,
    PoolPresence, PoolSelection, ReferenceHolder, StoragePool,
};

type SharedHost = Arc<Mutex<Ledger<Arc<ManualClock>>>>;

fn device() -> GpuDeviceKey {
    GpuDeviceKey {
        machine: machine(),
        device: digest("yougori/test/gpu/v1", &[&[0]]),
    }
}

fn charge(name: &str) -> LedgerCharge {
    LedgerCharge {
        operation: OperationId::new(format!("op-{name}")).unwrap(),
        priority: Priority::Foreground,
        retry_number: 0,
    }
}

fn session(name: &str) -> OperationId {
    OperationId::new(format!("session-{name}")).unwrap()
}

/// A KV-cache allocation of `bytes` for alice.
fn kv<C: Clock>(
    gpu: &mut GpuTier,
    ledger: &mut Ledger<C>,
    name: &str,
    bytes: u64,
) -> AllocationHandle {
    gpu.allocate_state(
        &alice(),
        MutableState::KvCache,
        bytes,
        &charge(name),
        ledger,
    )
    .unwrap()
}

/// Loads `bytes` of `object`'s weights for alice through a catalog read handle.
fn weights<C: Clock>(
    gpu: &mut GpuTier,
    catalog: &mut Catalog,
    ledger: &mut Ledger<C>,
    object: &ObjectRef,
    bytes: u64,
) -> AllocationHandle {
    let owner = alice();
    let lease = catalog
        .acquire_lease(
            &owner.scope(),
            &owner.execution,
            object.id(),
            Duration::from_secs(600),
        )
        .unwrap();
    let handle = catalog
        .open_read(&owner.scope(), &owner.execution, lease)
        .unwrap();
    let loaded = gpu
        .load_weights(
            &owner,
            object,
            &handle,
            catalog,
            bytes,
            &charge("load"),
            ledger,
        )
        .unwrap();
    drop(handle);
    catalog
        .release_lease(&owner.scope(), &owner.execution, lease)
        .unwrap();
    loaded
}

/// A host with 10 GiB of VRAM on GPU 0, storage quota, a catalog and a local storage
/// pool holding alice's model as its verified original.
struct Host {
    clock: Arc<ManualClock>,
    _root: TempDir,
    catalog: Catalog,
    local: LocalStorageTier,
    model: ObjectRef,
    ledger: SharedHost,
}

impl Host {
    fn new() -> Self {
        let clock = start();
        let root = TempDir::new().unwrap();
        let mut catalog = open_catalog(&root, Arc::clone(&clock));
        let mut ledger = ledger_on(Arc::clone(&clock), 10 * GIB, 64 * GIB);
        declare(&mut ledger, STORAGE, 10_000);
        let mut local = LocalStorageTier::new();
        local
            .add_pool(StoragePool {
                id: pool(),
                selection: PoolSelection::UserSelected,
                presence: PoolPresence::Present,
            })
            .unwrap();
        let model = import(
            &mut local,
            &mut catalog,
            &mut ledger,
            &[7u8; 3_000],
            ObjectRole::Original,
        );
        Self {
            clock,
            _root: root,
            catalog,
            local,
            model,
            ledger: Arc::new(Mutex::new(ledger)),
        }
    }
}

fn reservation_of(gpu: &GpuTier, allocation: AllocationHandle) -> ReservationId {
    gpu.reservation(allocation).unwrap()
}

fn holds<W: Clone + fmt::Display>(candidates: &[Candidate<W>]) -> Vec<(String, Hold)> {
    candidates
        .iter()
        .map(|candidate| (candidate.work.to_string(), candidate.hold))
        .collect()
}

fn reserve_vram(ledger: &SharedHost, name: &str, bytes: u64) -> Result<Admission, LedgerError> {
    ledger.lock().unwrap().reserve(load(name, bytes))
}

fn outcome(report: &LadderReport, step: ReclaimStep) -> StepOutcome {
    report
        .steps()
        .iter()
        .find(|report| report.step == step)
        .map(|report| report.outcome.clone())
        .unwrap()
}

#[test]
fn the_kv_of_finished_sessions_goes_and_closes_only_on_an_authoritative_observation() {
    let clock = start();
    let ledger: SharedHost = Arc::new(Mutex::new(ledger_on(clock, 10 * GIB, 64 * GIB)));
    let mut gpu = GpuTier::new(device(), None);
    let (dead, resumable, referenced, leased) = {
        let mut host = ledger.lock().unwrap();
        (
            kv(&mut gpu, &mut host, "dead", 2 * GIB),
            kv(&mut gpu, &mut host, "resumable", 2 * GIB),
            kv(&mut gpu, &mut host, "referenced", 2 * GIB),
            kv(&mut gpu, &mut host, "leased", 2 * GIB),
        )
    };
    gpu.add_reference(referenced, ReferenceHolder::Execution(alice()))
        .unwrap();
    let kv_of = [dead, resumable, referenced, leased];
    fn source<'a>(
        gpu: &'a mut GpuTier,
        ledger: &SharedHost,
        [dead, resumable, referenced, leased]: [AllocationHandle; 4],
    ) -> FinishedSessionKv<'a, Arc<ManualClock>> {
        FinishedSessionKv::new(gpu, Arc::clone(ledger))
            .finished(session("a"), [dead])
            .live(session("b"), [resumable])
            .finished(session("c"), [referenced])
            .finished(session("d"), [leased])
            .protect(leased, Hold::Leased(LeasedBy::Requests { leases: 1 }))
    }

    let mut step = DropLowValueCaches::new(Requester::ModelPlacement);
    let survey = step.prepare(&mut source(&mut gpu, &ledger, kv_of)).unwrap();
    assert_eq!(
        survey,
        Survey {
            free: 1,
            pinned: 1,
            leased: 2
        }
    );
    let generation = |allocation: AllocationHandle| allocation.generation();
    assert_eq!(
        holds(step.candidates()),
        [
            (
                format!(
                    "KV of session session-a in GPU allocation {}",
                    generation(dead)
                ),
                Hold::Free
            ),
            (
                format!(
                    "KV of session session-b in GPU allocation {}",
                    generation(resumable)
                ),
                Hold::Pinned(PinnedBy::LiveSession)
            ),
            (
                format!(
                    "KV of session session-c in GPU allocation {}",
                    generation(referenced)
                ),
                Hold::Leased(LeasedBy::Referenced { references: 1 })
            ),
            (
                format!(
                    "KV of session session-d in GPU allocation {}",
                    generation(leased)
                ),
                Hold::Leased(LeasedBy::Requests { leases: 1 })
            ),
        ]
    );

    // A load of 4 GiB finds 2 GiB free: the dead KV goes, and only it.
    let admission = {
        let mut ladder = ReclaimLadder::new();
        register_model_reclaimers(&mut ladder, [&mut step as &mut dyn ModelReclaimer]);
        ledger
            .lock()
            .unwrap()
            .reserve_reclaiming(load("next", 4 * GIB), &mut ladder)
    };
    let dead_reservation = reservation_of(&gpu, dead);
    assert_eq!(
        released(&admission.report, ReclaimStep::DropLowValueCaches),
        (Vec::new(), vec![dead_reservation], 0)
    );
    assert!(
        admission.admission.is_err(),
        "the dead KV counts until its release is observed"
    );
    let settlement = step
        .settle(&admission.report, &mut source(&mut gpu, &ledger, kv_of))
        .unwrap();
    assert_eq!(
        names(&settlement.stopped),
        [format!(
            "KV of session session-a in GPU allocation {}",
            generation(dead)
        )]
    );
    assert_eq!(settlement.awaiting_release(), [dead_reservation]);
    assert!(settlement.not_stopped.is_empty() && settlement.kept.is_empty());
    assert!(
        matches!(gpu.content(dead), Err(GpuRefusal::StaleHandle { .. })),
        "the tier freed it"
    );
    for kept in [resumable, referenced, leased] {
        let reservation = reservation_of(&gpu, kept);
        assert_eq!(
            state(&ledger.lock().unwrap(), reservation),
            Some(ReservationState::InUse)
        );
    }

    // A host-level allocation closes only on the host's own observation.
    let refused = confirm_freed_allocations(
        &mut ledger.lock().unwrap(),
        &settlement,
        SourceClass::GuestReport,
    );
    assert!(matches!(
        refused.as_slice(),
        [(reservation, Err(LedgerError::SourceNotAuthoritative { .. }))]
            if *reservation == dead_reservation
    ));
    assert_eq!(
        state(&ledger.lock().unwrap(), dead_reservation),
        Some(ReservationState::Releasing)
    );
    let confirmed = confirm_freed_allocations(
        &mut ledger.lock().unwrap(),
        &settlement,
        SourceClass::HostProbe,
    );
    assert!(matches!(
        confirmed.as_slice(),
        [(_, Ok(ReleaseOutcome::Released { .. }))]
    ));
    assert!(
        confirm_freed_allocations(
            &mut ledger.lock().unwrap(),
            &settlement,
            SourceClass::HostProbe
        )
        .is_empty(),
        "a closed reservation is left alone"
    );
    assert!(matches!(
        reserve_vram(&ledger, "next", 4 * GIB),
        Ok(Admission::Granted(_))
    ));
}

#[test]
fn dead_kv_goes_before_the_caches_of_value_on_rung_three() {
    let clock = start();
    let ledger: SharedHost = Arc::new(Mutex::new(ledger_on(clock, 10 * GIB, 64 * GIB)));
    let mut gpu = GpuTier::new(device(), None);
    let dead = kv(&mut gpu, &mut ledger.lock().unwrap(), "dead", 2 * GIB);
    // A cache of value in use, which would only begin releasing too.
    let cached = hold(
        &mut ledger.lock().unwrap(),
        Requester::ModelPlacement,
        "cached",
        vram(2 * GIB),
        true,
    );
    hold(
        &mut ledger.lock().unwrap(),
        Requester::ModelPlacement,
        "serving",
        vram(4 * GIB),
        true,
    );
    let mut store = Fake::new(
        Requester::ModelPlacement,
        vec![work("cached", &[cached], Hold::Free, 0.0)],
    );
    fn source<'a>(
        gpu: &'a mut GpuTier,
        ledger: &SharedHost,
        dead: AllocationHandle,
    ) -> FinishedSessionKv<'a, Arc<ManualClock>> {
        FinishedSessionKv::new(gpu, Arc::clone(ledger)).finished(session("a"), [dead])
    }

    let mut dead_kv = DropLowValueCaches::new(Requester::ModelPlacement);
    let mut caches = DropLowValueCaches::<String>::for_source(&store);
    dead_kv
        .prepare(&mut source(&mut gpu, &ledger, dead))
        .unwrap();
    caches.prepare(&mut store).unwrap();
    let (admission, registered) = {
        let mut ladder = ReclaimLadder::new();
        let registered = register_model_reclaimers(
            &mut ladder,
            [
                &mut dead_kv as &mut dyn ModelReclaimer,
                &mut caches as &mut dyn ModelReclaimer,
            ],
        );
        (
            ledger
                .lock()
                .unwrap()
                .reserve_reclaiming(load("next", 4 * GIB), &mut ladder),
            registered,
        )
    };
    assert_eq!(
        registered,
        [
            (ReclaimStep::DropLowValueCaches, Requester::ModelPlacement),
            (ReclaimStep::DropLowValueCaches, Requester::ModelPlacement),
        ]
    );
    // The dead KV is releasing; the cache of value gives nothing up, and the request
    // waits for that release.
    let rung: Vec<StepOutcome> = admission
        .report
        .steps()
        .iter()
        .filter(|report| report.step == ReclaimStep::DropLowValueCaches)
        .map(|report| report.outcome.clone())
        .collect();
    assert_eq!(
        rung,
        [
            StepOutcome::Released {
                returned: Vec::new(),
                releasing: vec![reservation_of(&gpu, dead)],
                refused: Vec::new(),
            },
            StepOutcome::Released {
                returned: Vec::new(),
                releasing: Vec::new(),
                refused: Vec::new(),
            },
        ]
    );
    assert!(admission.admission.is_err());
    let report = &admission.report;
    assert_eq!(
        dead_kv
            .settle(report, &mut source(&mut gpu, &ledger, dead))
            .unwrap()
            .stopped
            .len(),
        1
    );
    assert!(caches.settle(report, &mut store).unwrap().is_empty());
    assert!(store.stopped.is_empty());
    assert_eq!(
        state(&ledger.lock().unwrap(), cached),
        Some(ReservationState::InUse)
    );
}

#[test]
fn idle_weights_are_parked_clean_only_when_a_verified_copy_rebuilds_them() {
    let mut host = Host::new();
    let mut gpu = GpuTier::new(device(), None);
    let (idle, referenced, pinned) = {
        let mut ledger = host.ledger.lock().unwrap();
        (
            weights(
                &mut gpu,
                &mut host.catalog,
                &mut ledger,
                &host.model,
                2 * GIB,
            ),
            weights(
                &mut gpu,
                &mut host.catalog,
                &mut ledger,
                &host.model,
                2 * GIB,
            ),
            weights(
                &mut gpu,
                &mut host.catalog,
                &mut ledger,
                &host.model,
                2 * GIB,
            ),
        )
    };
    gpu.add_reference(referenced, ReferenceHolder::Execution(alice()))
        .unwrap();
    let model = host.model.clone();
    let mut step = ParkEligibleIdleModels::new(Requester::ModelPlacement);

    // With no copy to rebuild them, the idle weights are kept too, and the step says why.
    step.prepare(
        &mut IdleGpuWeights::new(&mut gpu, Arc::clone(&host.ledger))
            .weights_of(model.clone())
            .protect(pinned, Hold::Pinned(PinnedBy::Policy)),
    )
    .unwrap();
    let kept: Vec<Hold> = step
        .candidates()
        .iter()
        .map(|candidate| candidate.hold)
        .collect();
    assert_eq!(
        kept,
        [
            Hold::Pinned(PinnedBy::NoCanonicalState),
            Hold::Leased(LeasedBy::Referenced { references: 1 }),
            Hold::Pinned(PinnedBy::Policy),
        ]
    );
    let admission = {
        let mut ladder = ReclaimLadder::new();
        register_model_reclaimers(&mut ladder, [&mut step as &mut dyn ModelReclaimer]);
        host.ledger
            .lock()
            .unwrap()
            .reserve_reclaiming(load("next", 6 * GIB), &mut ladder)
    };
    assert_eq!(
        outcome(&admission.report, ReclaimStep::ParkEligibleIdleModels),
        StepOutcome::Declined(DeclineReason::Held {
            pinned: 2,
            leased: 1
        })
    );
    assert!(step
        .settle(
            &admission.report,
            &mut IdleGpuWeights::new(&mut gpu, Arc::clone(&host.ledger)).weights_of(model.clone()),
        )
        .unwrap()
        .is_empty());

    // The verified original in local storage rebuilds them: the idle weights are parked
    // clean, and nothing else.
    fn source<'a>(
        gpu: &'a mut GpuTier,
        host: &'a Host,
        pinned: AllocationHandle,
    ) -> IdleGpuWeights<'a, Arc<ManualClock>> {
        IdleGpuWeights::new(gpu, Arc::clone(&host.ledger))
            .weights_of(host.model.clone())
            .with_local(&host.local, &host.catalog)
            .protect(pinned, Hold::Pinned(PinnedBy::Policy))
    }
    step.prepare(&mut source(&mut gpu, &host, pinned)).unwrap();
    assert_eq!(step.candidates()[0].hold, Hold::Free);
    let admission = {
        let mut ladder = ReclaimLadder::new();
        register_model_reclaimers(&mut ladder, [&mut step as &mut dyn ModelReclaimer]);
        host.ledger
            .lock()
            .unwrap()
            .reserve_reclaiming(load("next", 6 * GIB), &mut ladder)
    };
    let idle_reservation = reservation_of(&gpu, idle);
    assert_eq!(
        released(&admission.report, ReclaimStep::ParkEligibleIdleModels),
        (Vec::new(), vec![idle_reservation], 0)
    );
    let settlement = step
        .settle(&admission.report, &mut source(&mut gpu, &host, pinned))
        .unwrap();
    assert_eq!(settlement.awaiting_release(), [idle_reservation]);
    assert_eq!(gpu.resident(&model), [referenced, pinned]);
    assert_eq!(
        host.catalog.status(&model.scope, model.id()),
        ObjectStatus::Published,
        "the copy that rebuilds them stays"
    );
    let confirmed = confirm_freed_allocations(
        &mut host.ledger.lock().unwrap(),
        &settlement,
        SourceClass::HostProbe,
    );
    assert_eq!(confirmed.len(), 1);
    assert!(matches!(
        reserve_vram(&host.ledger, "next", 6 * GIB),
        Ok(Admission::Granted(_))
    ));
}

#[test]
fn dead_kv_goes_on_rung_three_before_idle_weights_are_parked_on_rung_four() {
    let mut host = Host::new();
    let mut gpu = GpuTier::new(device(), None);
    let (dead, idle) = {
        let mut ledger = host.ledger.lock().unwrap();
        (
            kv(&mut gpu, &mut ledger, "dead", 2 * GIB),
            weights(
                &mut gpu,
                &mut host.catalog,
                &mut ledger,
                &host.model,
                2 * GIB,
            ),
        )
    };
    hold(
        &mut host.ledger.lock().unwrap(),
        Requester::ModelPlacement,
        "serving",
        vram(4 * GIB),
        true,
    );
    let model = host.model.clone();
    let mut sessions = DropLowValueCaches::new(Requester::ModelPlacement);
    let mut parking = ParkEligibleIdleModels::new(Requester::ModelPlacement);
    let round = |gpu: &mut GpuTier,
                 sessions: &mut DropLowValueCaches<SessionKv>,
                 parking: &mut ParkEligibleIdleModels<IdleWeights>,
                 bytes: u64| {
        sessions
            .prepare(
                &mut FinishedSessionKv::new(&mut *gpu, Arc::clone(&host.ledger))
                    .finished(session("a"), [dead]),
            )
            .unwrap();
        parking
            .prepare(
                &mut IdleGpuWeights::new(&mut *gpu, Arc::clone(&host.ledger))
                    .weights_of(model.clone())
                    .with_local(&host.local, &host.catalog),
            )
            .unwrap();
        let admission = {
            let mut ladder = ReclaimLadder::new();
            register_model_reclaimers(
                &mut ladder,
                [
                    &mut *parking as &mut dyn ModelReclaimer,
                    &mut *sessions as &mut dyn ModelReclaimer,
                ],
            );
            host.ledger
                .lock()
                .unwrap()
                .reserve_reclaiming(load("next", bytes), &mut ladder)
        };
        let settled = [
            sessions
                .settle(
                    &admission.report,
                    &mut FinishedSessionKv::new(&mut *gpu, Arc::clone(&host.ledger))
                        .finished(session("a"), [dead]),
                )
                .unwrap(),
            parking
                .settle(
                    &admission.report,
                    &mut IdleGpuWeights::new(&mut *gpu, Arc::clone(&host.ledger))
                        .weights_of(model.clone())
                        .with_local(&host.local, &host.catalog),
                )
                .unwrap(),
        ];
        (admission, settled)
    };

    // 2 GiB missing: the dead KV covers it on rung 3, so rung 4 parks nothing.
    let dead_reservation = reservation_of(&gpu, dead);
    let idle_reservation = reservation_of(&gpu, idle);
    let (admission, [kv_settled, weights_settled]) =
        round(&mut gpu, &mut sessions, &mut parking, 4 * GIB);
    assert_eq!(
        released(&admission.report, ReclaimStep::DropLowValueCaches),
        (Vec::new(), vec![dead_reservation], 0)
    );
    assert_eq!(
        released(&admission.report, ReclaimStep::ParkEligibleIdleModels),
        (Vec::new(), Vec::new(), 0)
    );
    assert_eq!(kv_settled.awaiting_release(), [dead_reservation]);
    assert!(weights_settled.is_empty());
    assert_eq!(gpu.resident(&model), [idle]);
    confirm_freed_allocations(
        &mut host.ledger.lock().unwrap(),
        &kv_settled,
        SourceClass::HostProbe,
    );

    // Once the KV is gone, only parking the weights can cover what a larger load misses.
    let (admission, [kv_settled, weights_settled]) =
        round(&mut gpu, &mut sessions, &mut parking, 6 * GIB);
    assert_eq!(
        outcome(&admission.report, ReclaimStep::DropLowValueCaches),
        StepOutcome::Declined(DeclineReason::NothingToReclaim)
    );
    assert!(kv_settled.is_empty());
    assert_eq!(weights_settled.awaiting_release(), [idle_reservation]);
    assert!(gpu.resident(&model).is_empty());
}

#[test]
fn nothing_under_a_transition_peak_or_shared_by_other_holders_is_given_up() {
    let clock = start();
    let ledger: SharedHost = Arc::new(Mutex::new(ledger_on(clock, 10 * GIB, 64 * GIB)));

    // The ledger's holds: an open peak on the reservation or on one it is carved from, and
    // a shared extent while any holder holds it.
    {
        let mut host = ledger.lock().unwrap();
        let runtime = hold(
            &mut host,
            Requester::ModelPlacement,
            "runtime",
            vram(4 * GIB),
            true,
        );
        // A child carved from the runtime's reservation, for the same execution.
        let child = match host.reserve(load("runtime", GIB).within(runtime)).unwrap() {
            Admission::Granted(child) => child,
            other => panic!("the child is granted: {other:?}"),
        };
        let other = hold(
            &mut host,
            Requester::ModelPlacement,
            "other",
            vram(GIB),
            true,
        );
        assert_eq!(ledger_hold(&host, child), None);
        host.begin_transition_peak(runtime, vram(GIB), Duration::from_secs(60))
            .unwrap();
        assert_eq!(
            ledger_hold(&host, child),
            Some(Hold::Pinned(PinnedBy::Transition))
        );
        assert_eq!(
            ledger_hold(&host, runtime),
            Some(Hold::Pinned(PinnedBy::Transition))
        );
        assert_eq!(ledger_hold(&host, other), None);

        let key = ExtentKey::new(digest("yougori/test/reclaim/extent/v1", &[b"base"]));
        let extent = host
            .share_extent(key, load("extent", GIB), other)
            .unwrap()
            .reservation();
        assert_eq!(
            ledger_hold(&host, extent),
            Some(Hold::Leased(LeasedBy::SharedExtent { holders: 1 }))
        );
        assert_eq!(
            host.leave_extent(key, other).unwrap(),
            ShareRelease::Released { amounts: vram(GIB) }
        );
        assert_eq!(ledger_hold(&host, extent), None);
    }

    // Finished-session KV under an open peak is kept, and the step says why.
    let mut gpu = GpuTier::new(device(), None);
    let dead = kv(&mut gpu, &mut ledger.lock().unwrap(), "dead", 2 * GIB);
    ledger
        .lock()
        .unwrap()
        .begin_transition_peak(
            reservation_of(&gpu, dead),
            vram(GIB),
            Duration::from_secs(60),
        )
        .unwrap();
    let mut step = DropLowValueCaches::new(Requester::ModelPlacement);
    step.prepare(
        &mut FinishedSessionKv::new(&mut gpu, Arc::clone(&ledger)).finished(session("a"), [dead]),
    )
    .unwrap();
    assert_eq!(
        step.candidates()[0].hold,
        Hold::Pinned(PinnedBy::Transition)
    );
    let admission = {
        let mut ladder = ReclaimLadder::new();
        register_model_reclaimers(&mut ladder, [&mut step as &mut dyn ModelReclaimer]);
        ledger
            .lock()
            .unwrap()
            .reserve_reclaiming(load("next", 8 * GIB), &mut ladder)
    };
    assert_eq!(
        outcome(&admission.report, ReclaimStep::DropLowValueCaches),
        StepOutcome::Declined(DeclineReason::Held {
            pinned: 1,
            leased: 0
        })
    );
    assert!(gpu.content(dead).is_ok());
}

#[test]
fn kv_mapped_or_taken_up_again_after_the_survey_is_reported_not_stopped() {
    let clock = start();
    let ledger: SharedHost = Arc::new(Mutex::new(ledger_on(clock, 10 * GIB, 64 * GIB)));
    let mut gpu = GpuTier::new(device(), None);
    let (mapped, resumed) = {
        let mut host = ledger.lock().unwrap();
        (
            kv(&mut gpu, &mut host, "mapped", 2 * GIB),
            kv(&mut gpu, &mut host, "resumed", 2 * GIB),
        )
    };
    hold(
        &mut ledger.lock().unwrap(),
        Requester::ModelPlacement,
        "serving",
        vram(6 * GIB),
        true,
    );
    // The tier does not list mappings, so a mapped allocation looks free to the survey.
    gpu.map(mapped, GIB).unwrap();
    let mut step = DropLowValueCaches::new(Requester::ModelPlacement);
    step.prepare(
        &mut FinishedSessionKv::new(&mut gpu, Arc::clone(&ledger))
            .finished(session("a"), [mapped])
            .finished(session("b"), [resumed]),
    )
    .unwrap();
    let admission = {
        let mut ladder = ReclaimLadder::new();
        register_model_reclaimers(&mut ladder, [&mut step as &mut dyn ModelReclaimer]);
        ledger
            .lock()
            .unwrap()
            .reserve_reclaiming(load("next", 4 * GIB), &mut ladder)
    };
    let (mapped_reservation, resumed_reservation) =
        (reservation_of(&gpu, mapped), reservation_of(&gpu, resumed));
    assert_eq!(
        released(&admission.report, ReclaimStep::DropLowValueCaches),
        (Vec::new(), vec![mapped_reservation, resumed_reservation], 0)
    );

    // Session b resumed before the settlement: its KV is kept.
    let settlement = step
        .settle(
            &admission.report,
            &mut FinishedSessionKv::new(&mut gpu, Arc::clone(&ledger))
                .finished(session("a"), [mapped])
                .live(session("b"), [resumed]),
        )
        .unwrap();
    assert!(settlement.stopped.is_empty());
    let errors: Vec<StopError> = settlement
        .not_stopped
        .iter()
        .map(|unstopped| unstopped.error.clone())
        .collect();
    assert_eq!(
        errors,
        [
            StopError::Gpu(Box::new(GpuRefusal::StillMapped { mappings: 1 })),
            StopError::Held {
                hold: Hold::Pinned(PinnedBy::LiveSession)
            },
        ]
    );
    assert!(settlement.awaiting_release().is_empty());
    assert!(
        confirm_freed_allocations(
            &mut ledger.lock().unwrap(),
            &settlement,
            SourceClass::HostProbe
        )
        .is_empty(),
        "nothing not freed is confirmed"
    );
    for (allocation, reservation) in [(mapped, mapped_reservation), (resumed, resumed_reservation)]
    {
        assert!(gpu.content(allocation).is_ok());
        assert_eq!(
            state(&ledger.lock().unwrap(), reservation),
            Some(ReservationState::Releasing),
            "it stays counted"
        );
    }
}

#[test]
fn idle_weights_a_pinned_copy_rebuilds_are_parked_before_those_only_storage_rebuilds() {
    let mut host = Host::new();
    declare(&mut host.ledger.lock().unwrap(), PINNED, GIB);
    let quick = import(
        &mut host.local,
        &mut host.catalog,
        &mut host.ledger.lock().unwrap(),
        &[8u8; 2_000],
        ObjectRole::Original,
    );
    let mut pinned = pinned_tier(&alice());
    {
        let owner = alice();
        let lease = host
            .catalog
            .acquire_lease(
                &owner.scope(),
                &owner.execution,
                quick.id(),
                Duration::from_secs(600),
            )
            .unwrap();
        let handle = host
            .catalog
            .open_read(&owner.scope(), &owner.execution, lease)
            .unwrap();
        pinned
            .pin_representation(
                &owner,
                &quick,
                &handle,
                &host.catalog,
                CopyState::VerifiedClean,
                &forecast(),
                &charge("pin"),
                &mut host.ledger.lock().unwrap(),
                host.clock.as_ref(),
            )
            .unwrap();
        drop(handle);
        host.catalog
            .release_lease(&owner.scope(), &owner.execution, lease)
            .unwrap();
    }
    let mut gpu = GpuTier::new(device(), None);
    let (slow, fast) = {
        let mut ledger = host.ledger.lock().unwrap();
        (
            weights(
                &mut gpu,
                &mut host.catalog,
                &mut ledger,
                &host.model,
                2 * GIB,
            ),
            weights(&mut gpu, &mut host.catalog, &mut ledger, &quick, 2 * GIB),
        )
    };
    hold(
        &mut host.ledger.lock().unwrap(),
        Requester::ModelPlacement,
        "serving",
        vram(6 * GIB),
        true,
    );
    let mut step = ParkEligibleIdleModels::new(Requester::ModelPlacement);
    step.prepare(
        &mut IdleGpuWeights::new(&mut gpu, Arc::clone(&host.ledger))
            .weights_of(host.model.clone())
            .weights_of(quick.clone())
            .with_pinned(&pinned)
            .with_local(&host.local, &host.catalog),
    )
    .unwrap();
    let ranks: Vec<(AllocationHandle, f64)> = step
        .candidates()
        .iter()
        .map(|candidate| (candidate.work.allocation, candidate.rank))
        .collect();
    assert_eq!(ranks, [(slow, 1.0), (fast, 0.0)]);

    // 2 GiB missing: the weights the pinned copy rebuilds go, though named last.
    let admission = {
        let mut ladder = ReclaimLadder::new();
        register_model_reclaimers(&mut ladder, [&mut step as &mut dyn ModelReclaimer]);
        host.ledger
            .lock()
            .unwrap()
            .reserve_reclaiming(load("next", 2 * GIB), &mut ladder)
    };
    assert_eq!(
        released(&admission.report, ReclaimStep::ParkEligibleIdleModels),
        (Vec::new(), vec![reservation_of(&gpu, fast)], 0)
    );
    let settlement = step
        .settle(
            &admission.report,
            &mut IdleGpuWeights::new(&mut gpu, Arc::clone(&host.ledger))
                .weights_of(host.model.clone())
                .weights_of(quick.clone())
                .with_pinned(&pinned)
                .with_local(&host.local, &host.catalog),
        )
        .unwrap();
    assert_eq!(settlement.stopped.len(), 1);
    assert_eq!(gpu.resident(&host.model), [slow]);
    assert!(gpu.resident(&quick).is_empty());
    assert!(pinned.copy_of(&quick).is_some(), "the pinned copy stays");
}
