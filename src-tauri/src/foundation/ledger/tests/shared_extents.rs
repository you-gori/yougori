//! Shared physical extents (S03; GPU part §2.7 and §3.7): an extent several holders share
//! is counted once and released only by its last holder, counted until observed when it
//! exists; cancelling one holder's execution leaves it to the others; holders share only
//! within one tenant and one demand; each holder is charged its share of the cost without
//! double counting; and an extent closed with its parent or released by its lifecycle
//! ends for every holder.

use std::collections::BTreeMap;

use super::*;
use crate::foundation::ids::SandboxBootGeneration;

fn key(name: &[u8]) -> ExtentKey {
    ExtentKey::new(digest("yougori/test/extent/v1", &[name]))
}

fn share_refusal(result: Result<ShareAdmission, LedgerError>) -> ShareRefusal {
    match result {
        Err(LedgerError::Ownership(OwnershipError::Share { refusal, .. })) => refusal,
        other => panic!("expected a share refusal, got {other:?}"),
    }
}

fn pinned_ring(execution: &str, bytes: u64) -> ReservationRequest {
    ReservationRequest::new(
        provenance(Requester::ModelPlacement, execution, "alpha"),
        Priority::Foreground,
        Amounts::new().pinned_host_ram_bytes(bytes),
    )
}

fn exits(record: &SharedExtentRecord) -> Vec<(ReservationId, HolderExit)> {
    record
        .spans
        .iter()
        .map(|span| (span.holder, span.left.unwrap().exit))
        .collect()
}

#[test]
fn a_shared_extent_is_counted_once_and_released_by_its_last_holder() {
    let clock = start();
    let mut ledger = ledger_on(&clock);
    let runtime = granted(ledger.reserve(on_gpu("exe-rt", Priority::Foreground, 23 * GB)));
    ledger.begin_create(runtime).unwrap();
    let process = |ledger: &mut Ledger<&ManualClock>| {
        granted(ledger.reserve(on_gpu("exe-rt", Priority::Foreground, 2 * GB).within(runtime)))
    };
    let (first, second, third) = (
        process(&mut ledger),
        process(&mut ledger),
        process(&mut ledger),
    );
    let weights = on_gpu("exe-rt", Priority::Foreground, 14 * GB).within(runtime);
    let weights_key = key(b"weights");

    let extent = match ledger.share_extent(weights_key, weights.clone(), first) {
        Ok(ShareAdmission::Reserved { reservation }) => reservation,
        other => panic!("expected a new extent, got {other:?}"),
    };
    // A second request for the same physical extent joins it: counted once.
    assert_eq!(
        ledger.share_extent(weights_key, weights.clone(), second),
        Ok(ShareAdmission::Joined {
            reservation: extent,
            holders: 2
        })
    );
    assert_eq!(ledger.join_extent(weights_key, third), Ok(3));
    assert_eq!(ledger.parent_room(runtime, vram(0)), Ok(3 * GB));
    assert_eq!(ledger.open_reservations().count(), 5);
    assert_eq!(ledger.extent_of(extent).unwrap().holders().count(), 3);

    // Nobody but its holders releases it.
    let held = Err(LedgerError::Ownership(OwnershipError::ExtentHeld {
        reservation: extent,
        key: weights_key,
        holders: 3,
    }));
    assert_eq!(ledger.cancel(extent), held);
    ledger.begin_create(extent).unwrap();
    assert_eq!(
        ledger.leave_extent(weights_key, first),
        Ok(ShareRelease::StillShared { holders: 2 })
    );
    assert_eq!(
        ledger.leave_extent(weights_key, second),
        Ok(ShareRelease::StillShared { holders: 1 })
    );
    assert_eq!(
        ledger.leave_extent(weights_key, third),
        Ok(ShareRelease::Pending)
    );
    // It exists, so it counts until its runtime reports the release.
    assert_eq!(ledger.parent_room(runtime, vram(0)), Ok(3 * GB));
    assert_eq!(
        ledger.reservation(extent).unwrap().state(),
        ReservationState::Releasing
    );
    ledger
        .confirm_release(extent, SourceClass::GuestReport)
        .unwrap();
    assert_eq!(ledger.parent_room(runtime, vram(0)), Ok(17 * GB));
    assert!(ledger.shared_extent(weights_key).is_none());
    let record = ledger.take_extent_records().pop().unwrap();
    assert_eq!(record.reservation, extent);
    assert_eq!(
        exits(&record),
        vec![
            (first, HolderExit::Left),
            (second, HolderExit::Left),
            (third, HolderExit::Left)
        ]
    );
    // The key can be shared again, as new memory.
    let again = ledger.share_extent(weights_key, weights, first).unwrap();
    assert!(matches!(again, ShareAdmission::Reserved { reservation } if reservation != extent));
}

#[test]
fn an_extent_never_created_returns_at_once_when_its_last_holder_leaves() {
    let clock = start();
    let mut ledger = ledger_on(&clock);
    let holder = granted(ledger.reserve(model_load("exe-a", "alpha", GIB, 0)));
    let ring_key = key(b"ring");
    ledger
        .share_extent(ring_key, pinned_ring("exe-a", 2 * GIB), holder)
        .unwrap();
    assert_eq!(ledger.reserved(PINNED), 2 * GIB);
    assert_eq!(
        ledger.leave_extent(ring_key, holder),
        Ok(ShareRelease::Released {
            amounts: Amounts::new().pinned_host_ram_bytes(2 * GIB)
        })
    );
    assert_eq!(ledger.reserved(PINNED), 0);
    assert_eq!(ledger.extent_records().len(), 1);
}

#[test]
fn cancelling_one_holders_execution_leaves_the_extent_to_the_others() {
    let clock = start();
    let mut ledger = ledger_on(&clock);
    let a = granted(ledger.reserve(model_load("exe-a", "alpha", GIB, 0)));
    let b = granted(ledger.reserve(model_load("exe-b", "alpha", GIB, 0)));
    ledger.begin_create(a).unwrap();
    ledger.begin_create(b).unwrap();
    let ring_key = key(b"ring");
    // Filed with the first holder's execution, which a revocation of that execution must
    // not take from the second.
    let ring = pinned_ring("exe-a", 2 * GIB);
    let extent = ledger
        .share_extent(ring_key, ring.clone(), a)
        .unwrap()
        .reservation();
    ledger.share_extent(ring_key, ring, b).unwrap();
    ledger.begin_create(extent).unwrap();

    let report = ledger.cancel_execution(&ExecutionId::new("exe-a").unwrap());
    assert_eq!(report.pending, vec![a]);
    assert!(report.released.is_empty());
    assert_eq!(
        ledger.reservation(extent).unwrap().state(),
        ReservationState::InUse
    );
    let shared = ledger.shared_extent(ring_key).unwrap();
    assert_eq!(
        shared.holders().map(|span| span.holder).collect::<Vec<_>>(),
        vec![b]
    );
    assert_eq!(
        shared.spans()[0].left.map(|left| left.exit),
        Some(HolderExit::HolderGone)
    );
    assert_eq!(ledger.reserved(PINNED), 2 * GIB);

    // The second holder's runtime stops: its last holder gone, the extent begins
    // releasing and counts until the host observes it.
    assert_eq!(ledger.cancel(b), Ok(ReleaseOutcome::Pending));
    assert_eq!(
        ledger.reservation(extent).unwrap().state(),
        ReservationState::Releasing
    );
    assert_eq!(ledger.reserved(PINNED), 2 * GIB);
    ledger
        .confirm_release(extent, SourceClass::HostProbe)
        .unwrap();
    assert_eq!(ledger.reserved(PINNED), 0);
    let record = ledger.take_extent_records().pop().unwrap();
    assert_eq!(
        exits(&record),
        vec![(a, HolderExit::HolderGone), (b, HolderExit::HolderGone)]
    );
}

#[test]
fn holders_share_an_extent_only_within_one_tenant_and_one_demand() {
    let clock = start();
    let mut ledger = ledger_on(&clock);
    let a = granted(ledger.reserve(model_load("exe-a", "alpha", GIB, 0)));
    let b = granted(ledger.reserve(model_load("exe-b", "alpha", GIB, 0)));
    let other = granted(ledger.reserve(model_load("exe-c", "beta", GIB, 0)));
    let ring_key = key(b"ring");
    let ring = pinned_ring("exe-a", 2 * GIB);

    // Refused before anything is reserved.
    assert_eq!(
        share_refusal(ledger.share_extent(ring_key, ring.clone(), other)),
        ShareRefusal::TenantMismatch { holder: other }
    );
    assert_eq!(ledger.reserved(PINNED), 0);
    let extent = ledger
        .share_extent(ring_key, ring.clone(), a)
        .unwrap()
        .reservation();
    assert_eq!(
        ledger.join_extent(ring_key, other),
        Err(LedgerError::Ownership(OwnershipError::Share {
            key: ring_key,
            refusal: ShareRefusal::TenantMismatch { holder: other }
        }))
    );
    assert_eq!(
        share_refusal(ledger.share_extent(ring_key, pinned_ring("exe-b", GIB), b)),
        ShareRefusal::DemandMismatch
    );
    assert_eq!(
        share_refusal(ledger.share_extent(ring_key, ring.clone(), a)),
        ShareRefusal::AlreadyHolding { holder: a }
    );
    assert_eq!(
        ledger.leave_extent(ring_key, b),
        Err(LedgerError::Ownership(OwnershipError::Share {
            key: ring_key,
            refusal: ShareRefusal::NotAHolder { holder: b }
        }))
    );
    assert_eq!(
        ledger.leave_extent(key(b"nothing"), a),
        Err(LedgerError::Ownership(OwnershipError::Share {
            key: key(b"nothing"),
            refusal: ShareRefusal::NotShared
        }))
    );
    // A holder is never carved from the extent it holds.
    ledger.begin_create(extent).unwrap();
    let inside = granted(ledger.reserve(pinned_ring("exe-a", GIB).within(extent)));
    assert_eq!(
        ledger.join_extent(ring_key, inside),
        Err(LedgerError::Ownership(OwnershipError::Share {
            key: ring_key,
            refusal: ShareRefusal::HolderInsideExtent { holder: inside }
        }))
    );
    // A releasing holder holds nothing new.
    ledger.begin_create(b).unwrap();
    ledger.cancel(b).unwrap();
    assert_eq!(
        ledger.join_extent(ring_key, b),
        Err(LedgerError::Ownership(OwnershipError::Share {
            key: ring_key,
            refusal: ShareRefusal::HolderNotOpen { holder: b }
        }))
    );
    assert_eq!(ledger.reserved(PINNED), 2 * GIB);
    assert_eq!(ledger.extent_of(extent).unwrap().holders().count(), 1);
    // Nobody new joins a releasing extent.
    let c = granted(ledger.reserve(model_load("exe-d", "alpha", GIB, 0)));
    ledger.leave_extent(ring_key, a).unwrap();
    assert_eq!(
        ledger.join_extent(ring_key, c),
        Err(LedgerError::Ownership(OwnershipError::Share {
            key: ring_key,
            refusal: ShareRefusal::Releasing
        }))
    );
}

#[test]
fn each_holder_is_charged_its_share_without_double_counting() {
    let clock = start();
    let mut ledger = ledger_on(&clock);
    let holders: Vec<ReservationId> = ["exe-a", "exe-b", "exe-c"]
        .into_iter()
        .map(|name| granted(ledger.reserve(model_load(name, "alpha", GIB, 0))))
        .collect();
    let (a, b, c) = (holders[0], holders[1], holders[2]);
    let ring_key = key(b"ring");
    // Seven bytes, so that a three-way split leaves a remainder.
    let ring = pinned_ring("exe-a", 7);
    let extent = ledger
        .share_extent(ring_key, ring, a)
        .unwrap()
        .reservation();
    ledger.begin_create(extent).unwrap();
    clock.advance(10 * SECOND);
    ledger.join_extent(ring_key, b).unwrap();
    clock.advance(10 * SECOND);
    ledger.join_extent(ring_key, c).unwrap();
    clock.advance(5 * SECOND);
    let partial: u128 = ledger
        .extent_costs(ring_key, clock.now())
        .unwrap()
        .iter()
        .map(|cost| cost.amount_nanoseconds)
        .sum();
    assert_eq!(
        partial,
        ledger
            .reservation(extent)
            .unwrap()
            .held_amount_nanoseconds(PINNED, clock.now())
    );
    clock.advance(5 * SECOND);
    ledger.leave_extent(ring_key, a).unwrap();
    clock.advance(10 * SECOND);
    ledger.leave_extent(ring_key, b).unwrap();
    clock.advance(10 * SECOND);
    assert_eq!(ledger.leave_extent(ring_key, c), Ok(ShareRelease::Pending));
    clock.advance(5 * SECOND);
    ledger
        .confirm_release(extent, SourceClass::HostProbe)
        .unwrap();

    let record = ledger.take_extent_records().pop().unwrap();
    let costs: BTreeMap<ReservationId, u128> = record
        .costs
        .iter()
        .map(|cost| {
            assert_eq!(cost.resource, PINNED);
            (cost.holder, cost.amount_nanoseconds)
        })
        .collect();
    let ten = 7 * 10 * SECOND.as_nanos();
    // a alone; a and b; a, b and c (a takes the indivisible nanobyte); b and c; c alone;
    // and c pays the release that followed it.
    assert_eq!(costs[&a], ten + ten / 2 + ten / 3 + 1);
    assert_eq!(costs[&b], ten / 2 + ten / 3 + ten / 2);
    assert_eq!(costs[&c], ten / 3 + ten / 2 + ten + ten / 2);
    let closed = ledger
        .closed_records()
        .iter()
        .find(|closed| closed.id() == extent)
        .unwrap();
    assert_eq!(
        costs.values().sum::<u128>(),
        closed.held_amount_nanoseconds(PINNED, record.closed_at)
    );
    assert_eq!(costs.values().sum::<u128>(), 7 * 55 * SECOND.as_nanos());
    let executions: Vec<&str> = record
        .costs
        .iter()
        .map(|cost| cost.provenance.execution.as_str())
        .collect();
    assert_eq!(executions, vec!["exe-a", "exe-b", "exe-c"]);
}

#[test]
fn an_extent_closed_with_its_parent_or_released_by_its_lifecycle_ends_for_every_holder() {
    let clock = start();
    let mut ledger = ledger_on(&clock);
    // Closed with its parent.
    let runtime = granted(ledger.reserve(on_gpu("exe-rt", Priority::Foreground, 20 * GB)));
    let process =
        granted(ledger.reserve(on_gpu("exe-rt", Priority::Foreground, GB).within(runtime)));
    let weights_key = key(b"weights");
    ledger
        .share_extent(
            weights_key,
            on_gpu("exe-rt", Priority::Foreground, 14 * GB).within(runtime),
            process,
        )
        .unwrap();
    assert!(matches!(
        ledger.cancel(runtime),
        Ok(ReleaseOutcome::Released { .. })
    ));
    assert!(ledger.shared_extent(weights_key).is_none());
    let record = ledger.take_extent_records().pop().unwrap();
    assert_eq!(exits(&record), vec![(process, HolderExit::ExtentGone)]);

    // Released by the lifecycle that owns it, whatever its holders.
    let a = granted(ledger.reserve(model_load("exe-a", "alpha", GIB, 0)));
    let b = granted(ledger.reserve(model_load("exe-b", "alpha", GIB, 0)));
    let ring_key = key(b"ring");
    let extent = ledger
        .share_extent(ring_key, pinned_ring("exe-pool", 2 * GIB), a)
        .unwrap()
        .reservation();
    ledger.join_extent(ring_key, b).unwrap();
    let lifecycle = Lifecycle::sandbox_boot(
        tenant("alpha"),
        ExecutionId::new("exe-pool").unwrap(),
        SandboxBootGeneration::FIRST,
    );
    ledger.bind_lifecycle(extent, lifecycle.clone()).unwrap();
    let report = ledger.end_lifecycle(&lifecycle, LifecycleEnd::Revoked);
    assert_eq!(report.released, vec![extent]);
    assert_eq!(ledger.reserved(PINNED), 0);
    let record = ledger.take_extent_records().pop().unwrap();
    assert_eq!(
        exits(&record),
        vec![(a, HolderExit::ExtentGone), (b, HolderExit::ExtentGone)]
    );
    // The holders themselves are untouched.
    assert!(ledger.reservation(a).is_some() && ledger.reservation(b).is_some());
}
