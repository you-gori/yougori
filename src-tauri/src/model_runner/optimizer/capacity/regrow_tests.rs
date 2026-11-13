//! Grow-back on the one host ledger (G03: a model trimmed beside a neighbour regains context
//! when the neighbour leaves): the extra bytes are admitted by the ledger as a reservation of
//! their own and held as in use while offered, join the grant only on the runner's word or
//! report, close through the next probe when the runner does not take them, are shed first by a
//! later trim and leave with the grant.
use super::coadmit_tests::{kept, later, none, open_roots, qwen_facts};
use super::tests::{sample, world, GIB};
use super::*;
use crate::foundation::ids::ManualClock;
use crate::foundation::ledger::ReservationState;

/// A, stamped to fill the GPU, trimmed to the fair share for B, and B granted the same share
/// beside it (as `coadmit_tests` shows): the accounting, A's stamp and the share A accepted.
fn trimmed_beside_b() -> (Accounting<Arc<ManualClock>>, ContextDemand, GrantTerms) {
    let facts = qwen_facts();
    let stamped = facts
        .longest_context(24 * GIB - RESERVE - HOST_HEADROOM)
        .unwrap();
    let before = sample(GIB);
    let (_, mut a) = world(&before);
    a.settle_and_admit(&before, "a", Some(stamped.demand), None)
        .unwrap();
    let resident_facts = BTreeMap::from([("a".to_owned(), (facts, stamped.context))]);
    let now = sample(3 * GIB);
    let decided = a
        .settle_and_coadmit(
            &now,
            "b",
            stamped.demand,
            Some(stamped.context),
            Some(facts),
            &Residents {
                kept: &kept(&[("a", 2 * GIB)]),
                trimmed: &none(),
                facts: &resident_facts,
                evictable: &[],
            },
        )
        .unwrap();
    let Coadmission::Trim(trims) = decided else {
        panic!("a trim first: {decided:?}")
    };
    let asked = trims[0].1;
    let trimmed = BTreeMap::from([("a".to_owned(), asked.bytes)]);
    let granted = a
        .settle_and_coadmit(
            &now,
            "b",
            stamped.demand,
            Some(stamped.context),
            Some(facts),
            &Residents {
                kept: &kept(&[("a", 2 * GIB)]),
                trimmed: &trimmed,
                facts: &resident_facts,
                evictable: &[],
            },
        )
        .unwrap();
    assert_eq!(granted, Coadmission::Granted(asked));
    (a, stamped, asked)
}

fn candidates(stamped: &ContextDemand, current: u64) -> BTreeMap<String, (Facts, u64, u64)> {
    BTreeMap::from([("a".to_owned(), (qwen_facts(), stamped.context, current))])
}

fn holding(bytes: u64, context: u64) -> BTreeMap<String, (u64, u64)> {
    BTreeMap::from([("a".to_owned(), (bytes, context))])
}

fn state(a: &Accounting<Arc<ManualClock>>, root: ReservationId) -> Option<ReservationState> {
    a.ledger
        .lock()
        .unwrap()
        .reservation(root)
        .map(|record| record.state())
}

fn total_reserved(a: &Accounting<Arc<ManualClock>>) -> u64 {
    a.ledger
        .lock()
        .unwrap()
        .reserved(ResourceKey::vram(a.device.unwrap()))
}

#[test]
fn a_trimmed_resident_grows_back_to_its_stamp_when_its_neighbour_leaves_and_takes_it_only_on_its_word(
) {
    let (mut a, stamped, asked) = trimmed_beside_b();
    let share = asked.context.unwrap();
    // B leaves: only A is kept. B's grant returns through the probe and A's whole stamp fits.
    let offers = a
        .settle_and_offer(
            &later(2 * GIB, 20),
            &kept(&[("a", 2 * GIB)]),
            &holding(asked.bytes, share),
            &candidates(&stamped, share),
        )
        .unwrap();
    let full = GrantTerms {
        bytes: stamped.demand.bytes,
        context: Some(stamped.context),
    };
    assert_eq!(offers, vec![("a".to_owned(), full)]);
    assert!(!a.grants.contains_key("b"));
    // The extra bytes are a reservation of their own, admitted at background priority and in
    // use already (a lost answer must not let them expire); the grant has not taken them.
    let growth = a.grants["a"].offered.unwrap().growth.unwrap();
    assert_eq!(growth.bytes, stamped.demand.bytes - asked.bytes);
    assert_eq!(state(&a, growth.root), Some(ReservationState::InUse));
    assert_eq!(
        a.ledger
            .lock()
            .unwrap()
            .reservation(growth.root)
            .unwrap()
            .priority(),
        Priority::Background
    );
    assert_eq!(open_roots(&a), 2);
    assert_eq!(total_reserved(&a), stamped.demand.bytes);
    assert_eq!(
        a.grants["a"].reserved, asked.bytes,
        "not taken before the runner's word"
    );
    // While the runner's answer is unknown, nothing more is offered.
    assert!(a
        .settle_and_offer(
            &later(2 * GIB, 40),
            &kept(&[("a", 2 * GIB)]),
            &BTreeMap::new(),
            &candidates(&stamped, share),
        )
        .unwrap()
        .is_empty());
    // Other terms than the offer's change nothing; the offer's own are taken.
    a.growth_taken("a", asked);
    assert!(a.grants["a"].offered.is_some());
    a.growth_taken("a", full);
    assert_eq!(a.grants["a"].reserved, stamped.demand.bytes);
    assert_eq!(a.grants["a"].growth, vec![growth]);
    assert!(a.grants["a"].offered.is_none());
    // At its stamp nothing more is offered, and the runner's report agrees.
    assert!(a
        .settle_and_offer(
            &later(2 * GIB, 60),
            &kept(&[("a", 2 * GIB)]),
            &holding(stamped.demand.bytes, stamped.context),
            &BTreeMap::new(),
        )
        .unwrap()
        .is_empty());
    assert_eq!(total_reserved(&a), stamped.demand.bytes);
}

#[test]
fn growth_a_runner_reports_taking_joins_its_grant_and_growth_it_did_not_take_closes_through_the_next_probe(
) {
    let (mut a, stamped, asked) = trimmed_beside_b();
    let share = asked.context.unwrap();
    let offer =
        |a: &mut Accounting<Arc<ManualClock>>, secs, holds: BTreeMap<String, (u64, u64)>| {
            a.settle_and_offer(
                &later(2 * GIB, secs),
                &kept(&[("a", 2 * GIB)]),
                &holds,
                &candidates(&stamped, share),
            )
            .unwrap()
        };
    assert_eq!(offer(&mut a, 20, holding(asked.bytes, share)).len(), 1);
    let growth = a.grants["a"].offered.unwrap().growth.unwrap();
    // The runner's next report says it still holds what it held: the growth is cancelled on
    // the ledger (releasing, still counted) and nothing more is offered to it for a while.
    assert!(offer(&mut a, 40, holding(asked.bytes, share)).is_empty());
    assert!(a.grants["a"].offered.is_none());
    assert_eq!(a.grants["a"].reserved, asked.bytes);
    assert_eq!(state(&a, growth.root), Some(ReservationState::Releasing));
    assert_eq!(
        total_reserved(&a),
        stamped.demand.bytes,
        "counted until the probe confirms"
    );
    // The next probe closes it.
    assert!(offer(&mut a, 60, holding(asked.bytes, share)).is_empty());
    assert_eq!(state(&a, growth.root), None);
    assert_eq!(total_reserved(&a), asked.bytes);
    assert_eq!(open_roots(&a), 1);
    // A runner that reports holding the offered terms has taken them, with or without its
    // answer: a fresh grant offered again after the pause is taken from the report alone.
    let (mut b, stamped, asked) = trimmed_beside_b();
    let share = asked.context.unwrap();
    let offers = b
        .settle_and_offer(
            &later(2 * GIB, 20),
            &kept(&[("a", 2 * GIB)]),
            &holding(asked.bytes, share),
            &candidates(&stamped, share),
        )
        .unwrap();
    let terms = offers[0].1;
    b.settle_and_offer(
        &later(2 * GIB, 40),
        &kept(&[("a", 2 * GIB)]),
        &holding(terms.bytes, terms.context.unwrap()),
        &candidates(&stamped, terms.context.unwrap()),
    )
    .unwrap();
    assert!(b.grants["a"].offered.is_none());
    assert_eq!(b.grants["a"].reserved, stamped.demand.bytes);
    assert_eq!(total_reserved(&b), stamped.demand.bytes);
}

#[test]
fn growth_is_offered_only_within_what_the_ledger_admits_and_never_on_a_changing_reading() {
    let (mut a, stamped, asked) = trimmed_beside_b();
    let share = asked.context.unwrap();
    let before = total_reserved(&a);
    // B is still resident and the outside gigabyte still in use: no room for a growth of
    // two context steps (the fair share's rounding leaves less), nothing reserved or offered.
    assert!(a
        .settle_and_offer(
            &later(4 * GIB, 20),
            &kept(&[("a", 2 * GIB), ("b", GIB)]),
            &holding(asked.bytes, share),
            &candidates(&stamped, share),
        )
        .unwrap()
        .is_empty());
    assert_eq!(total_reserved(&a), before);
    // B left, but a program outside Yougori took all the memory it returned: the probe
    // charges it as unmanaged and nothing fits beside A's grant.
    assert!(a
        .settle_and_offer(
            &later(24 * GIB - RESERVE, 40),
            &kept(&[("a", 2 * GIB)]),
            &holding(asked.bytes, share),
            &candidates(&stamped, share),
        )
        .unwrap()
        .is_empty());
    assert_eq!(
        open_roots(&a),
        1,
        "B's grant returned, nothing new reserved"
    );
    assert_eq!(total_reserved(&a), asked.bytes);
    // A reading taken while the GPU's use is changing (the outside program returning its
    // memory within the settle window) offers nothing; the next settled one does.
    assert!(a
        .settle_and_offer(
            &later(2 * GIB, 45),
            &kept(&[("a", 2 * GIB)]),
            &holding(asked.bytes, share),
            &candidates(&stamped, share),
        )
        .unwrap()
        .is_empty());
    assert!(a.growth_due(), "looked again at the next pass");
    assert_eq!(
        a.settle_and_offer(
            &later(2 * GIB, 70),
            &kept(&[("a", 2 * GIB)]),
            &holding(asked.bytes, share),
            &candidates(&stamped, share),
        )
        .unwrap()
        .len(),
        1
    );
}

#[test]
fn a_later_trim_sheds_the_growth_first_and_the_grant_leaves_with_every_growth() {
    let (mut a, stamped, asked) = trimmed_beside_b();
    let share = asked.context.unwrap();
    let offers = a
        .settle_and_offer(
            &later(2 * GIB, 20),
            &kept(&[("a", 2 * GIB)]),
            &holding(asked.bytes, share),
            &candidates(&stamped, share),
        )
        .unwrap();
    a.growth_taken("a", offers[0].1);
    let growth = a.grants["a"].growth[0];
    let base = a.grants["a"].root;
    // C arrives: A is trimmed again, below its first share. The growth goes first (released
    // whole), then the first reservation is held to the rest.
    let keep = asked.bytes - GIB;
    let mut ledger = a.ledger.lock().unwrap();
    let resource = ResourceKey::vram(a.device.unwrap());
    let mut grant = a.grants["a"].clone();
    let released = shrink(&mut ledger, &mut grant, keep, resource).unwrap();
    drop(ledger);
    assert_eq!(released, vec![growth.root]);
    assert!(grant.growth.is_empty());
    assert_eq!(grant.reserved, keep);
    assert_eq!(state(&a, growth.root), None);
    assert_eq!(
        a.ledger
            .lock()
            .unwrap()
            .reservation(base)
            .unwrap()
            .current()
            .get(resource),
        keep
    );
    // A smaller trim of a grant that still holds part of a growth reconciles that growth down
    // and leaves the first reservation as it was.
    let (mut b, stamped, asked) = trimmed_beside_b();
    let share = asked.context.unwrap();
    let offers = b
        .settle_and_offer(
            &later(2 * GIB, 20),
            &kept(&[("a", 2 * GIB)]),
            &holding(asked.bytes, share),
            &candidates(&stamped, share),
        )
        .unwrap();
    b.growth_taken("a", offers[0].1);
    let growth = b.grants["a"].growth[0];
    let keep = stamped.demand.bytes - GIB;
    let resource = ResourceKey::vram(b.device.unwrap());
    let mut grant = b.grants["a"].clone();
    shrink(&mut b.ledger.lock().unwrap(), &mut grant, keep, resource).unwrap();
    assert_eq!(grant.growth[0].bytes, growth.bytes - GIB);
    assert_eq!(grant.reserved, keep);
    assert_eq!(
        b.ledger
            .lock()
            .unwrap()
            .reservation(growth.root)
            .unwrap()
            .current()
            .get(resource),
        growth.bytes - GIB
    );
    // A leaves with its growth: every root closes through the probe.
    b.settle_and_release(&later(GIB, 40), &BTreeMap::new())
        .unwrap();
    assert_eq!(open_roots(&b), 0);
    assert_eq!(total_reserved(&b), 0);
    assert!(b.roots.is_empty());
}

#[tokio::test]
async fn the_runner_is_asked_to_grow_with_its_fence_and_the_engine_takes_only_what_it_answers() {
    use std::sync::Mutex as Shared;
    let (a, stamped, asked) = trimmed_beside_b();
    let share = asked.context.unwrap();
    let accounting = Shared::new(a);
    let resident = json!({"status": "ready", "optimizer": {"controlProtocol": 1, "instanceId": "a".repeat(32),
        "sequence": 4, "enabled": true, "pinned": false, "resident": true, "loading": false, "releaseUncertain": false,
        "active": 0, "pending": 0, "allocatedBytes": 2 * GIB, "capacityBytes": asked.bytes, "capacityContext": share}});
    let residents = vec![("a".to_owned(), resident)];
    let sent = Shared::new(Vec::new());
    let answer = |taken: bool| {
        let sent = &sent;
        move |_id: String, body: Value| {
            sent.lock().unwrap().push(body.clone());
            let mut h = json!({"status": "ready", "optimizer": {"controlProtocol": 1, "instanceId": "a".repeat(32),
                "sequence": 5, "enabled": true, "pinned": false, "resident": true, "loading": false,
                "releaseUncertain": false, "active": 0, "pending": 0}});
            h["grown"] = json!(taken);
            h["terms"] = json!({"bytes": body["bytes"], "context": body["context"]});
            h["controlAck"] = json!({"action": "grow", "instanceId": body["expectedInstanceId"],
                "expectedSequence": body["expectedSequence"], "sequence": 5});
            async move { Ok::<Value, String>(h) }
        }
    };
    let shutdown = CancellationToken::new();
    let candidates = candidates(&stamped, share);
    // A runner that does not acknowledge leaves the offer held, untaken.
    let refused = answer(false);
    let grown = regrow(
        &residents,
        &shutdown,
        &refused,
        || async { Ok(later(2 * GIB, 20)) },
        |snapshot, kept, holding| {
            accounting
                .lock()
                .unwrap()
                .settle_and_offer(snapshot, kept, holding, &candidates)
        },
        |id, terms| accounting.lock().unwrap().growth_taken(id, terms),
    )
    .await
    .unwrap();
    assert!(grown.is_empty());
    {
        let a = accounting.lock().unwrap();
        assert!(a.grants["a"].offered.is_some());
        assert_eq!(a.grants["a"].reserved, asked.bytes);
    }
    let body = sent.lock().unwrap()[0].clone();
    assert_eq!(body["action"], "grow");
    assert_eq!(body["expectedSequence"], 4);
    assert_eq!(body["bytes"], stamped.demand.bytes);
    assert_eq!(body["context"], stamped.context);
    // Its report says it holds what it held: withdrawn. After the pause it is asked again and
    // answers taking the terms: the grant has them.
    {
        let mut a = accounting.lock().unwrap();
        a.settle_and_offer(
            &later(2 * GIB, 40),
            &kept(&[("a", 2 * GIB)]),
            &holding(asked.bytes, share),
            &candidates,
        )
        .unwrap();
        a.grants.get_mut("a").unwrap().declined = None;
    }
    let taken = answer(true);
    let grown = regrow(
        &residents,
        &shutdown,
        &taken,
        || async { Ok(later(2 * GIB, 60)) },
        |snapshot, kept, holding| {
            accounting
                .lock()
                .unwrap()
                .settle_and_offer(snapshot, kept, holding, &candidates)
        },
        |id, terms| accounting.lock().unwrap().growth_taken(id, terms),
    )
    .await
    .unwrap();
    let full = GrantTerms {
        bytes: stamped.demand.bytes,
        context: Some(stamped.context),
    };
    assert_eq!(grown, vec![("a".to_owned(), full)]);
    let a = accounting.lock().unwrap();
    assert!(a.grants["a"].offered.is_none());
    assert_eq!(a.grants["a"].reserved, stamped.demand.bytes);
    assert_eq!(total_reserved(&a), stamped.demand.bytes);
}
