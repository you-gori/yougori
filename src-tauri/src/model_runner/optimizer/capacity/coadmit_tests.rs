//! Co-residency on the one host ledger (G03 "co-residency of two models whose demands fit";
//! S03 "reclaiming reservations on the actual admission path"; GPU-W05 "reclaim unused
//! scratch" and "park eligible idle models"): what a kept resident is credited with, when a
//! second model is granted beside it, when residents are trimmed to a fair share, when the
//! idle resident is parked, and when a shorter context is granted instead.
use super::tests::{sample, world, GIB};
use super::*;
use crate::foundation::ids::ManualClock;
use crate::foundation::ledger::ReservationState;

const MIB: u64 = 1024 * 1024;
/// Qwen2.5-0.5B-Instruct's weights and attention shape, as the Transformers tests use them.
const QWEN_WEIGHTS: u64 = 988_097_824;

pub(super) fn qwen_facts() -> Facts {
    Facts::new(
        QWEN_WEIGHTS,
        AttentionShape {
            layers: 24,
            heads: 14,
            kv_heads: 2,
            head_dim: 64,
            hidden: 896,
            bytes: 2,
            context: 32768,
        },
    )
}

pub(super) fn transformers(bytes: u64) -> Demand {
    Demand {
        profile: Profile::Transformers,
        bytes,
    }
}

pub(super) fn kept(entries: &[(&str, u64)]) -> BTreeMap<String, u64> {
    entries
        .iter()
        .map(|(id, bytes)| ((*id).to_owned(), *bytes))
        .collect()
}

pub(super) fn none() -> BTreeMap<String, u64> {
    BTreeMap::new()
}

pub(super) fn no_facts() -> BTreeMap<String, (Facts, u64)> {
    BTreeMap::new()
}

/// `sample(used)` observed `secs` after now: a later, settled probe for the settle guard
/// (an instant ahead of now has no age, so the freshness check passes).
pub(super) fn later(used: u64, secs: u64) -> Snapshot {
    let mut snapshot = sample(used);
    snapshot.observed = std::time::Instant::now() + Duration::from_secs(secs);
    snapshot
}

pub(super) fn open_roots(a: &Accounting<Arc<ManualClock>>) -> usize {
    a.ledger
        .lock()
        .unwrap()
        .open_reservations()
        .filter(|r| r.parent().is_none())
        .count()
}

pub(super) fn reserved_of(a: &Accounting<Arc<ManualClock>>, env: &str) -> u64 {
    let grant = &a.grants[env];
    let ledger = a.ledger.lock().unwrap();
    let device = a.device.unwrap();
    ledger
        .reservation(grant.root)
        .unwrap()
        .current()
        .get(ResourceKey::vram(device))
}

#[test]
fn a_kept_resident_is_credited_with_what_it_reports_at_most_its_reservation_and_a_fitting_demand_is_granted_beside_it(
) {
    // Model A is granted 10 GiB on an otherwise empty GPU (1 GiB used by the host).
    let before = sample(GIB);
    let (_, mut a) = world(&before);
    a.settle_and_admit(&before, "a", Some(transformers(10 * GIB)), None)
        .unwrap();
    // A is resident, holding 8 GiB; the probe sees 9 GiB used. Crediting A's 8 GiB leaves
    // 1 GiB unmanaged, so B's 10 GiB fits: 24 - 0.25 reserve - 1 unmanaged - 10 A = 12.75.
    let now = sample(9 * GIB);
    let granted = a
        .settle_and_coadmit(
            &now,
            "b",
            transformers(10 * GIB),
            Some(4096),
            None,
            &Residents {
                kept: &kept(&[("a", 8 * GIB)]),
                trimmed: &none(),
                facts: &no_facts(),
                evictable: &[],
            },
        )
        .unwrap();
    assert_eq!(
        granted,
        Coadmission::Granted(GrantTerms {
            bytes: 10 * GIB,
            context: Some(4096)
        })
    );
    assert_eq!(open_roots(&a), 2, "both grants stay open");
    assert!(a.grants.contains_key("a") && a.grants.contains_key("b"));
    // A runner is never credited beyond its reservation: A claiming 15 GiB of its 10 GiB
    // grant while the probe sees 20 GiB used leaves 10 GiB unmanaged, so C's 5 GiB does
    // not fit (24 - 0.25 - 10 - 10 - 10 < 5) and nothing is evictable: refused with why.
    let crowded = later(20 * GIB, 20);
    let refused = a
        .settle_and_coadmit(
            &crowded,
            "c",
            transformers(5 * GIB),
            None,
            None,
            &Residents {
                kept: &kept(&[("a", 15 * GIB), ("b", 10 * GIB)]),
                trimmed: &none(),
                facts: &no_facts(),
                evictable: &[],
            },
        )
        .unwrap_err();
    assert!(refused.starts_with(NOT_AVAILABLE), "{refused}");
    assert_eq!(open_roots(&a), 2);
}

#[test]
fn an_idle_resident_is_parked_for_a_demand_that_does_not_fit_beside_it_and_the_grant_follows_its_release(
) {
    let before = sample(GIB);
    let (_, mut a) = world(&before);
    a.settle_and_admit(&before, "a", Some(transformers(14 * GIB)), None)
        .unwrap();
    // B wants 14 GiB too; beside A only 24 - 0.25 - 1 - 14 = 8.75 GiB is left. A is idle.
    let now = sample(13 * GIB);
    let decided = a
        .settle_and_coadmit(
            &now,
            "b",
            transformers(14 * GIB),
            Some(8192),
            None,
            &Residents {
                kept: &kept(&[("a", 12 * GIB)]),
                trimmed: &none(),
                facts: &no_facts(),
                evictable: &["a".to_owned()],
            },
        )
        .unwrap();
    assert_eq!(decided, Coadmission::Evict(vec!["a".to_owned()]));
    // A's reservation is releasing: it still counts until the host sees the memory free.
    {
        let ledger = a.ledger.lock().unwrap();
        let root = a.grants["a"].root;
        assert_eq!(
            ledger
                .open_reservations()
                .find(|r| r.id() == root)
                .map(|r| r.state()),
            Some(ReservationState::Releasing)
        );
    }
    assert!(a.grants.contains_key("a"), "kept until the probe confirms");
    // The scheduler unloaded A; the probe shows its memory gone; A is no longer kept.
    let after = sample(GIB);
    let granted = a
        .settle_and_coadmit(
            &after,
            "b",
            transformers(14 * GIB),
            Some(8192),
            None,
            &Residents {
                kept: &none(),
                trimmed: &none(),
                facts: &no_facts(),
                evictable: &[],
            },
        )
        .unwrap();
    assert_eq!(
        granted,
        Coadmission::Granted(GrantTerms {
            bytes: 14 * GIB,
            context: Some(8192)
        })
    );
    assert!(!a.grants.contains_key("a") && a.grants.contains_key("b"));
    assert_eq!(open_roots(&a), 1);
}

#[test]
fn two_transformers_models_share_the_gpu_fairly_the_resident_is_trimmed_then_the_newcomer_granted_its_share(
) {
    let facts = qwen_facts();
    let budget = 24 * GIB - RESERVE - HOST_HEADROOM;
    let stamped = facts.longest_context(budget).unwrap();
    assert_eq!(
        stamped.context, 9728,
        "the stamp fills the GPU for this model"
    );
    // A is resident under its full stamp, holding 2 GiB of it.
    let before = sample(GIB);
    let (_, mut a) = world(&before);
    a.settle_and_admit(&before, "a", Some(stamped.demand), None)
        .unwrap();
    let mut resident_facts = BTreeMap::new();
    resident_facts.insert("a".to_owned(), (facts, stamped.context));
    let now = sample(3 * GIB);
    // B, stamped the same, does not fit beside A's stamp; A is asked to hold itself to the
    // fair share first (nothing is reserved yet), even though A is idle: trimming comes
    // before parking on the ladder.
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
                evictable: &["a".to_owned()],
            },
        )
        .unwrap();
    let Coadmission::Trim(trims) = decided else {
        panic!("a trim first: {decided:?}")
    };
    assert_eq!(trims.len(), 1);
    let (env, asked) = &trims[0];
    assert_eq!(env, "a");
    let share = asked.context.unwrap();
    assert!(share >= MIN_CONTEXT && share < stamped.context && share % CONTEXT_STEP == 0);
    assert_eq!(asked.bytes, facts.demand_at(share).unwrap());
    // Two shares fit the GPU less the reserve and the unmanaged gigabyte.
    assert!(2 * asked.bytes <= 24 * GIB - RESERVE - GIB);
    assert_eq!(
        reserved_of(&a, "a"),
        stamped.demand.bytes,
        "nothing changed yet"
    );
    assert_eq!(open_roots(&a), 1);
    // A accepted the trim; the probe confirms the GPU's state; A's reservation shrinks to what
    // it accepted and B is granted its share.
    let mut trimmed = BTreeMap::new();
    trimmed.insert("a".to_owned(), asked.bytes);
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
                evictable: &["a".to_owned()],
            },
        )
        .unwrap();
    assert_eq!(
        granted,
        Coadmission::Granted(GrantTerms {
            bytes: asked.bytes,
            context: Some(share)
        })
    );
    assert_eq!(reserved_of(&a, "a"), asked.bytes);
    assert_eq!(a.grants["a"].reserved, asked.bytes);
    assert_eq!(reserved_of(&a, "b"), asked.bytes);
    assert_eq!(open_roots(&a), 2, "both resident, neither parked");
    // Memory freed outside between the trim and the grant never lifts the newcomer above
    // the resident it asked to make room: with the GPU emptier at the second settle, B still
    // gets the share A was held to.
    let (_, mut c) = world(&before);
    c.settle_and_admit(&before, "a", Some(stamped.demand), None)
        .unwrap();
    let emptier = sample(GIB + 512 * MIB);
    let granted = c
        .settle_and_coadmit(
            &emptier,
            "b",
            stamped.demand,
            Some(stamped.context),
            Some(facts),
            &Residents {
                kept: &kept(&[("a", GIB)]),
                trimmed: &trimmed,
                facts: &resident_facts,
                evictable: &[],
            },
        )
        .unwrap();
    assert_eq!(
        granted,
        Coadmission::Granted(GrantTerms {
            bytes: asked.bytes,
            context: Some(share)
        })
    );
    // A busy A that accepted less than asked (it holds more) leaves B the longest context
    // that fits what remains, shorter than the share.
    let (_, mut b) = world(&before);
    b.settle_and_admit(&before, "a", Some(stamped.demand), None)
        .unwrap();
    let mut partly = BTreeMap::new();
    partly.insert("a".to_owned(), asked.bytes + 6 * GIB);
    let granted = b
        .settle_and_coadmit(
            &now,
            "b",
            stamped.demand,
            Some(stamped.context),
            Some(facts),
            &Residents {
                kept: &kept(&[("a", 2 * GIB)]),
                trimmed: &partly,
                facts: &resident_facts,
                evictable: &[],
            },
        )
        .unwrap();
    let Coadmission::Granted(terms) = granted else {
        panic!("granted shorter: {granted:?}")
    };
    assert!(terms.bytes < asked.bytes && terms.context.unwrap() < share);
    assert_eq!(reserved_of(&b, "a"), asked.bytes + 6 * GIB);
}

#[test]
fn under_outside_pressure_beyond_the_residents_reservations_nothing_is_trimmed_for_a_share_that_is_not_there(
) {
    let facts = qwen_facts();
    let stamped = facts
        .longest_context(24 * GIB - RESERVE - HOST_HEADROOM)
        .unwrap();
    // A is resident at the share two models get (6,656 tokens), pinned (not evictable).
    let before = sample(GIB);
    let (_, mut a) = world(&before);
    let share = facts.demand_at(6656).unwrap();
    a.settle_and_admit(&before, "a", Some(transformers(share)), None)
        .unwrap();
    let mut resident_facts = BTreeMap::new();
    resident_facts.insert("a".to_owned(), (facts, stamped.context));
    // A host process holds 20 GiB beside A's 1 GiB: 21 GiB used. The table is 24 - 0.25 - 20
    // = 3.75 GiB for both models together, less than two shortest contexts need, so no
    // share exists: A keeps its grant untrimmed and B is refused with why.
    let pressed = sample(21 * GIB);
    let refused = a
        .settle_and_coadmit(
            &pressed,
            "b",
            stamped.demand,
            Some(stamped.context),
            Some(facts),
            &Residents {
                kept: &kept(&[("a", GIB)]),
                trimmed: &none(),
                facts: &resident_facts,
                evictable: &[],
            },
        )
        .unwrap_err();
    assert!(refused.starts_with(NOT_AVAILABLE), "{refused}");
    assert_eq!(reserved_of(&a, "a"), share);
    assert_eq!(open_roots(&a), 1);
    // With 12 GiB held outside, the table is 11.75 GiB: both fit at a shorter context, so A
    // is asked to trim to it and B gets the same.
    let lighter = later(13 * GIB, 20);
    let decided = a
        .settle_and_coadmit(
            &lighter,
            "b",
            stamped.demand,
            Some(stamped.context),
            Some(facts),
            &Residents {
                kept: &kept(&[("a", GIB)]),
                trimmed: &none(),
                facts: &resident_facts,
                evictable: &[],
            },
        )
        .unwrap();
    let Coadmission::Trim(trims) = decided else {
        panic!("a trim: {decided:?}")
    };
    let asked = &trims[0].1;
    assert!(asked.bytes < share && 2 * asked.bytes <= 24 * GIB - RESERVE - 12 * GIB);
}

#[test]
fn beside_a_resident_without_facts_the_newcomer_takes_the_longest_context_that_fits_never_more_than_its_stamp(
) {
    let before = sample(GIB);
    let (_, mut a) = world(&before);
    // A holds 16 GiB under a stamp made before the facts were recorded: it cannot be trimmed.
    a.settle_and_admit(&before, "a", Some(transformers(16 * GIB)), None)
        .unwrap();
    let facts = qwen_facts();
    let stamped = facts
        .longest_context(24 * GIB - RESERVE - HOST_HEADROOM)
        .unwrap();
    let now = sample(17 * GIB);
    let granted = a
        .settle_and_coadmit(
            &now,
            "b",
            stamped.demand,
            Some(stamped.context),
            Some(facts),
            &Residents {
                kept: &kept(&[("a", 16 * GIB)]),
                trimmed: &none(),
                facts: &no_facts(),
                evictable: &[],
            },
        )
        .unwrap();
    let Coadmission::Granted(terms) = granted else {
        panic!("granted at a shorter context: {granted:?}")
    };
    // 24 - 0.25 - 1 - 16 = 6.75 GiB is left for B.
    assert!(terms.bytes < stamped.demand.bytes && terms.bytes <= 6 * GIB + 768 * MIB);
    let context = terms.context.unwrap();
    assert!(context >= MIN_CONTEXT && context < stamped.context && context % CONTEXT_STEP == 0);
    assert_eq!(a.grants["b"].reserved, terms.bytes);
    // Without its own facts (a stamp made before co-residency) nothing shorter is derived.
    let (_, mut b) = world(&before);
    b.settle_and_admit(&before, "a", Some(transformers(16 * GIB)), None)
        .unwrap();
    let refused = b
        .settle_and_coadmit(
            &now,
            "b",
            stamped.demand,
            Some(stamped.context),
            None,
            &Residents {
                kept: &kept(&[("a", 16 * GIB)]),
                trimmed: &none(),
                facts: &no_facts(),
                evictable: &[],
            },
        )
        .unwrap_err();
    assert!(refused.starts_with(NOT_AVAILABLE), "{refused}");
    // A vLLM demand is never shortened: the runner does not hold itself to a grant.
    let refused = b
        .settle_and_coadmit(
            &now,
            "c",
            Demand::vllm(8 * GIB),
            None,
            Some(facts),
            &Residents {
                kept: &kept(&[("a", 16 * GIB)]),
                trimmed: &none(),
                facts: &no_facts(),
                evictable: &[],
            },
        )
        .unwrap_err();
    assert!(refused.starts_with(NOT_AVAILABLE), "{refused}");
}

#[test]
fn the_facts_stamp_reads_back_and_the_fair_share_is_bounded_by_each_models_own_stamp() {
    let facts = qwen_facts();
    let mut options = BTreeMap::new();
    options.insert(SHAPE.to_owned(), facts.write());
    options.insert(CONTEXT.to_owned(), "9728".to_owned());
    assert_eq!(Facts::read(&options), Some(facts));
    assert_eq!(stamped_context(&options), Some(9728));
    assert_eq!(facts.served_context(), 32768);
    let budget = 24 * GIB - RESERVE - HOST_HEADROOM;
    let on_budget = facts.longest_context(budget).unwrap();
    assert_eq!(on_budget.context % CONTEXT_STEP, 0);
    assert!(on_budget.demand.bytes <= budget);
    assert!(
        facts.longest_context(GIB).is_none(),
        "the weights alone exceed 1 GiB"
    );
    // Two Qwen models share 20 GiB at the same context; a resident stamped shorter keeps
    // its shorter stamp and leaves the newcomer the rest.
    let share = fair_context(20 * GIB, &[(facts, 9728)], (facts, 9728)).unwrap();
    assert!(share >= MIN_CONTEXT && 2 * facts.demand_at(share).unwrap() <= 20 * GIB);
    let uneven = fair_context(20 * GIB, &[(facts, 2048)], (facts, 9728)).unwrap();
    assert!(
        uneven > share,
        "the newcomer gets what the short resident leaves"
    );
    assert!(facts.demand_at(2048).unwrap() + facts.demand_at(uneven).unwrap() <= 20 * GIB);
    assert_eq!(fair_context(2 * GIB, &[(facts, 9728)], (facts, 9728)), None);
    options.insert(SHAPE.to_owned(), "{\"weights\": 0}".to_owned());
    assert_eq!(Facts::read(&options), None);
    options.remove(SHAPE);
    assert_eq!(Facts::read(&options), None);
}

#[test]
fn the_parker_gives_up_idle_roots_in_order_until_the_shortfall_is_covered_and_nothing_is_parked_when_it_fits(
) {
    let before = sample(GIB);
    let (_, mut a) = world(&before);
    a.settle_and_admit(&before, "a", Some(transformers(6 * GIB)), None)
        .unwrap();
    let now = sample(7 * GIB);
    // B 6 GiB beside A: fits (24 - 0.25 - 1 - 6 = 16.75), so nothing is parked even
    // though A is evictable; the stamped context stays.
    let granted = a
        .settle_and_coadmit(
            &now,
            "b",
            transformers(6 * GIB),
            Some(2048),
            None,
            &Residents {
                kept: &kept(&[("a", 6 * GIB)]),
                trimmed: &none(),
                facts: &no_facts(),
                evictable: &["a".to_owned()],
            },
        )
        .unwrap();
    assert!(matches!(granted, Coadmission::Granted(_)));
    assert_eq!(open_roots(&a), 2);
    // C wants 12 GiB: 24 - 0.25 - 1 - 12 = 10.75 left, 1.25 short; A alone (6 GiB) covers
    // it, so only A is named, not B.
    let crowded = later(13 * GIB, 20);
    let decided = a
        .settle_and_coadmit(
            &crowded,
            "c",
            transformers(12 * GIB),
            None,
            None,
            &Residents {
                kept: &kept(&[("a", 6 * GIB), ("b", 6 * GIB)]),
                trimmed: &none(),
                facts: &no_facts(),
                evictable: &["a".to_owned(), "b".to_owned()],
            },
        )
        .unwrap();
    assert_eq!(decided, Coadmission::Evict(vec!["a".to_owned()]));
}

#[test]
fn the_waiting_words_name_what_holds_the_gpu_and_what_to_do_and_leave_other_reasons_alone() {
    let refusal = format!("{NOT_AVAILABLE}: VRAM on GPU x: 22583493552 bytes requested, 0 bytes free under this host's capacity after its supervisor reserve; park eligible idle models declined, nothing to reclaim");
    let words = waiting_words(&refusal, "Qwen A, Qwen B");
    assert!(words.starts_with("Not enough GPU memory is free for this model beside Qwen A, Qwen B and the programs outside Yougori"), "{words}");
    assert!(
        words.contains("close other programs that use the GPU, or stop a model")
            && words.contains("pinned or busy"),
        "{words}"
    );
    assert!(
        !words.contains("22583493552"),
        "no raw bytes for the person"
    );
    assert_eq!(
        waiting_words("GPU admission cancelled.", "Qwen A"),
        "GPU admission cancelled."
    );
}

#[test]
fn a_share_is_computed_only_once_the_gpus_use_has_settled_so_a_returning_spike_trims_no_resident() {
    let facts = qwen_facts();
    let stamped = facts
        .longest_context(24 * GIB - RESERVE - HOST_HEADROOM)
        .unwrap();
    let before = sample(GIB);
    let (_, mut a) = world(&before);
    let share = facts.demand_at(6656).unwrap();
    a.settle_and_admit(&before, "a", Some(transformers(share)), None)
        .unwrap();
    let mut resident_facts = BTreeMap::new();
    resident_facts.insert("a".to_owned(), (facts, stamped.context));
    let kept_a = kept(&[("a", GIB)]);
    let no_trim = none();
    let residents = Residents {
        kept: &kept_a,
        trimmed: &no_trim,
        facts: &resident_facts,
        evictable: &[],
    };
    // Under 20 GiB of outside use B is refused (as the pressure test shows).
    let pressed = sample(21 * GIB);
    assert!(a
        .settle_and_coadmit(
            &pressed,
            "b",
            stamped.demand,
            Some(stamped.context),
            Some(facts),
            &residents
        )
        .is_err());
    // Two seconds later the outside program is returning its memory: 9 GiB in use, 12 GiB
    // less than the last probe. No share is computed on that reading: B waits, A is not asked
    // to trim to a share that will be stale once the memory is back.
    let mut returning = sample(9 * GIB);
    returning.observed = pressed.observed + Duration::from_secs(2);
    let waiting = a
        .settle_and_coadmit(
            &returning,
            "b",
            stamped.demand,
            Some(stamped.context),
            Some(facts),
            &residents,
        )
        .unwrap_err();
    assert!(
        waiting.contains("changing") && waiting.contains("settles"),
        "{waiting}"
    );
    assert_eq!(reserved_of(&a, "a"), share);
    // Once settled (the next probe within a half gibibyte of the last), the share is computed:
    // both at 6,656 tokens, so A is not trimmed and B granted the same.
    let mut settled = sample(GIB + 256 * MIB);
    settled.observed = returning.observed + Duration::from_secs(2);
    let mut again = sample(GIB + 256 * MIB);
    again.observed = settled.observed + Duration::from_secs(2);
    assert!(
        matches!(
            a.settle_and_coadmit(
                &settled,
                "b",
                stamped.demand,
                Some(stamped.context),
                Some(facts),
                &residents
            ),
            Err(_)
        ),
        "the first settled reading after a change still differs from the changing one"
    );
    let granted = a
        .settle_and_coadmit(
            &again,
            "b",
            stamped.demand,
            Some(stamped.context),
            Some(facts),
            &residents,
        )
        .unwrap();
    // A keeps its share untrimmed; B takes the longest context that fits beside it (A\'s
    // reservation is below the two-model share, so B\'s is at least the share).
    let Coadmission::Granted(terms) = granted else {
        panic!("granted: {granted:?}")
    };
    assert!(
        terms.context.unwrap() >= 6656 && terms.bytes >= share,
        "{terms:?}"
    );
    assert!(
        terms.bytes <= 24 * GIB - RESERVE - 256 * MIB - share,
        "{terms:?}"
    );
    assert_eq!(reserved_of(&a, "a"), share);
}

#[test]
fn a_dead_runners_grant_returns_through_the_probe_while_the_residents_keep_theirs() {
    // A alone, then B beside A: two grants.
    let before = sample(GIB);
    let (_, mut a) = world(&before);
    a.settle_and_admit(&before, "a", Some(transformers(6 * GIB)), None)
        .unwrap();
    let now = sample(7 * GIB);
    let granted = a
        .settle_and_coadmit(
            &now,
            "b",
            transformers(6 * GIB),
            Some(2048),
            None,
            &Residents {
                kept: &kept(&[("a", 6 * GIB)]),
                trimmed: &none(),
                facts: &no_facts(),
                evictable: &[],
            },
        )
        .unwrap();
    assert!(matches!(granted, Coadmission::Granted(_)));
    assert_eq!(open_roots(&a), 2);
    // B's runner died: the engine saw its environment end, the probe shows only A's bytes.
    // The idle reconciliation keeps A and releases B through the probe (the one-resident
    // release could settle only when every grant was gone at once).
    let later = sample(7 * GIB);
    a.settle_and_release(&later, &kept(&[("a", 6 * GIB)]))
        .unwrap();
    assert_eq!(open_roots(&a), 1);
    assert!(a.grants.contains_key("a") && !a.grants.contains_key("b"));
    assert_eq!(reserved_of(&a, "a"), 6 * GIB);
    // With every runner gone, everything returns.
    a.settle_and_release(&sample(GIB), &none()).unwrap();
    assert_eq!(open_roots(&a), 0);
    assert!(a.grants.is_empty());
}
