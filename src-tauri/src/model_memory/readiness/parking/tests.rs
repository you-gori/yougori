use std::collections::BTreeMap;

use super::*;
use crate::foundation::evidence::{Backend, BackendModeRules, BackendRelease, EvidenceRefusal};
use crate::foundation::ids::{digest, ContentKey};
use crate::foundation::report::Quantile;
use crate::model_memory::backends::{
    ExperimentApproval, KvRetention, LevelSemantics, PinnedFeature,
};
use crate::model_memory::readiness::claim::{ClaimOutcome, EvidenceClass};
use crate::model_memory::readiness::test_support::{
    discard_rules, documented_vllm_levels, factory, label, profile, runtime, verified,
    vllm_recorded, vllm_with_sleep, weights, Loaded, GB, MILLIS,
};
use crate::model_memory::residency::eviction::{ContentState, Verification};

fn extent(name: &str, copies: Vec<ReconstructibleCopy>) -> ImmutableAllocation {
    ImmutableAllocation {
        gpu: GpuCopy {
            content: Content::Immutable(ContentKey::of(name.as_bytes())),
            state: ContentState::Clean,
            bytes: GB,
        },
        copies,
    }
}

fn local(name: &str) -> ReconstructibleCopy {
    verified(CopyTier::LocalStorage, ContentKey::of(name.as_bytes()))
}

fn graph_pool(state: ContentState) -> ImmutableAllocation {
    ImmutableAllocation {
        gpu: GpuCopy {
            content: Content::GraphPool {
                weights: weights("model-a"),
                execution_key: digest("yougori/test/readiness/graph/v1", &[b"key"]),
            },
            state,
            bytes: GB / 4,
        },
        copies: Vec::new(),
    }
}

fn allocations() -> Vec<ImmutableAllocation> {
    vec![
        extent("extent-0", vec![local("extent-0")]),
        extent("extent-1", vec![local("extent-1")]),
        graph_pool(ContentState::Clean),
    ]
}

fn model_copy() -> Option<ReconstructibleCopy> {
    Some(verified(CopyTier::LocalStorage, weights("model-a")))
}

fn eligibility_on(
    loaded: &Loaded,
    approvals: &[ExperimentApproval],
    copy: Option<ReconstructibleCopy>,
    allocations: &[ImmutableAllocation],
) -> ParkEligibility {
    park_eligibility(
        &loaded.runtime,
        &loaded.registry,
        approvals,
        weights("model-a"),
        copy,
        allocations,
    )
}

#[test]
fn clean_drop_needs_a_verified_reconstructible_copy_of_every_allocation() {
    let vllm = vllm_with_sleep();
    let eligible = eligibility_on(&vllm, &[], model_copy(), &allocations());
    let plan = eligible.clean_drop.clone().unwrap();
    assert!(matches!(
        &plan.route,
        CleanDropRoute::BackendSleep { plan } if plan.level() == SleepLevel::new(2)
    ));
    assert_eq!(
        plan.reloads
            .iter()
            .map(|(index, proof, tier)| (*index, proof.content(), *tier))
            .collect::<Vec<_>>(),
        vec![
            (0, ContentKey::of(b"extent-0"), CopyTier::LocalStorage),
            (1, ContentKey::of(b"extent-1"), CopyTier::LocalStorage)
        ]
    );
    assert_eq!(plan.recaptured, vec![2]);
    assert!(!plan.keeps_virtual_reservations);
    assert!(eligible.allows(ParkOption::CleanDrop));
    assert!(eligible.allows(ParkOption::Restart));
    assert_eq!(
        eligible.sleep_with_cpu_copy.as_ref().unwrap().level(),
        SleepLevel::new(1)
    );
    assert!(allocations()[0].clean_and_reconstructible());
    assert!(!allocations()[2].clean_and_reconstructible());

    let refused = |allocations: Vec<ImmutableAllocation>| {
        eligibility_on(&vllm, &[], model_copy(), &allocations)
            .clean_drop
            .unwrap_err()
    };
    // An unverified copy, a copy of other content and a copy that may vanish do not count.
    for copy in [
        ReconstructibleCopy {
            tier: CopyTier::LocalStorage,
            verification: Verification::Unverified,
        },
        local("extent-9"),
        verified(CopyTier::ReclaimableHost, ContentKey::of(b"extent-1")),
        verified(CopyTier::AuthorizedPeer, ContentKey::of(b"extent-1")),
    ] {
        let mut set = allocations();
        set[1] = extent("extent-1", vec![copy]);
        assert!(matches!(
            refused(set),
            ParkRefusal::NoVerifiedCopy { index: 1, .. }
        ));
        assert!(!extent("extent-1", vec![copy]).clean_and_reconstructible());
    }
    let mut no_copy = allocations();
    no_copy[0].copies.clear();
    assert!(matches!(
        refused(no_copy),
        ParkRefusal::NoVerifiedCopy { index: 0, .. }
    ));
    let mut dirty = allocations();
    dirty[1].gpu.state = ContentState::Dirty;
    assert_eq!(refused(dirty), ParkRefusal::Dirty { index: 1 });
    let mut dirty_pool = allocations();
    dirty_pool[2] = graph_pool(ContentState::Dirty);
    assert_eq!(refused(dirty_pool), ParkRefusal::Dirty { index: 2 });
    let session = ImmutableAllocation {
        gpu: GpuCopy {
            content: Content::SessionState(digest("yougori/test/readiness/kv/v1", &[b"s"])),
            state: ContentState::Clean,
            bytes: GB,
        },
        copies: Vec::new(),
    };
    assert_eq!(
        refused(vec![session]),
        ParkRefusal::NotImmutable { index: 0 }
    );
    assert_eq!(refused(Vec::new()), ParkRefusal::NoAllocations);

    // The backend must be able to drop the weights while the process lives.
    let unverified_model_copy = Some(ReconstructibleCopy {
        tier: CopyTier::LocalStorage,
        verification: Verification::Unverified,
    });
    let no_route = eligibility_on(&vllm, &[], unverified_model_copy, &allocations());
    assert!(matches!(
        no_route.clean_drop,
        Err(ParkRefusal::NoBackendRoute { ref sleep, discard_mode: None, .. }) if sleep.len() == 1
    ));
    let offload_only = runtime(
        BackendRelease::new(Backend::Vllm, "0.31.0").unwrap(),
        BackendModeRules::recorded(),
        &[crate::foundation::evidence::Optimization::SleepWeightOffload],
        BTreeMap::from([(
            SleepLevel::new(1),
            LevelSemantics {
                weights: WeightRetention::OffloadedToHost,
                kv_cache: KvRetention::Discarded,
            },
        )]),
        &[PinnedFeature::StagedWake],
    );
    let only_sleep = eligibility_on(&offload_only, &[], model_copy(), &allocations());
    assert!(matches!(
        only_sleep.clean_drop,
        Err(ParkRefusal::NoBackendRoute { ref sleep, .. }) if sleep.is_empty()
    ));
    assert!(only_sleep.allows(ParkOption::SleepWithCpuCopy));
    let discard_only = runtime(
        BackendRelease::new(Backend::Vllm, "0.31.0").unwrap(),
        discard_rules(),
        &[
            crate::foundation::evidence::Optimization::SleepWeightOffload,
            crate::foundation::evidence::Optimization::SleepWeightDiscard,
        ],
        BTreeMap::from([(
            SleepLevel::new(2),
            documented_vllm_levels()[&SleepLevel::new(2)],
        )]),
        &[PinnedFeature::StagedWake],
    );
    assert!(matches!(
        eligibility_on(&discard_only, &[], model_copy(), &allocations()).sleep_with_cpu_copy,
        Err(ParkRefusal::NoCpuCopyLevel { .. })
    ));
}

#[test]
fn the_approved_fixed_address_arena_keeps_virtual_reservations() {
    let release = BackendRelease::new(Backend::Transformers, "5.18.0").unwrap();
    let transformers = runtime(
        release.clone(),
        BackendModeRules::recorded(),
        &[],
        BTreeMap::new(),
        &[],
    );
    let without = eligibility_on(&transformers, &[], model_copy(), &allocations());
    assert!(matches!(
        without.clean_drop,
        Err(ParkRefusal::NoBackendRoute {
            arena: TechniqueRefusal::ExperimentNotApproved { .. },
            ..
        })
    ));
    let approval = ExperimentApproval {
        technique: Technique::FixedAddressArena,
        release,
        record: digest("yougori/test/readiness/approval/v1", &[b"arena"]),
    };
    let with = eligibility_on(&transformers, &[approval], model_copy(), &allocations());
    // Transformers reports no sleep levels, so standard sleep is not available.
    assert!(!with.allows(ParkOption::SleepWithCpuCopy));
    let plan = with.clean_drop.unwrap();
    assert_eq!(plan.route, CleanDropRoute::VmmArena);
    assert!(plan.keeps_virtual_reservations);
}

#[test]
fn a_discarding_level_needs_core_01_evidence_for_sleep_weight_discard() {
    // The recorded rules do not record sleep weight discard for any release, so level 2
    // cannot be the clean-drop route even though the pinned release reports it.
    let recorded = vllm_recorded();
    let eligible = eligibility_on(&recorded, &[], model_copy(), &allocations());
    match &eligible.clean_drop {
        Err(ParkRefusal::NoBackendRoute {
            sleep,
            discard_mode: Some(EvidenceRefusal::Missing { .. }),
            ..
        }) => assert!(sleep.is_empty()),
        other => panic!("expected the discard mode to be refused, got {other:?}"),
    }
    // Standard sleep is still planned under the offload mode's own evidence.
    assert!(eligible.allows(ParkOption::SleepWithCpuCopy));
}

#[test]
fn every_park_follows_the_placement_lifecycle() {
    for option in ParkOption::ALL {
        let path = option.lifecycle();
        assert_eq!(path.check(), Ok(()));
        assert_eq!(path.park.first(), Some(&StateKind::Serving));
        assert_eq!(path.park.get(1), Some(&StateKind::Draining));
        assert_eq!(path.wake.last(), Some(&StateKind::Serving));
        assert_eq!(path.process_survives, option != ParkOption::Restart);
    }
    // Parking without draining, or serving again without activating, is refused.
    assert_eq!(
        check_path(&[StateKind::Serving, StateKind::Parked]),
        Err(IllegalTransition {
            from: StateKind::Serving,
            to: StateKind::Parked
        })
    );
    assert_eq!(
        check_path(&[StateKind::Parked, StateKind::Serving]),
        Err(IllegalTransition {
            from: StateKind::Parked,
            to: StateKind::Serving
        })
    );
}

fn policy(reuse_probability: f64) -> ParkPolicy {
    ParkPolicy {
        reuse_probability,
        idle_seconds: 600.0,
        weight_per_park_second: 1.0,
        weight_per_wake_second: 1.0,
        weight_per_retained_host_byte_second: 0.0,
        weight_per_interrupted_request: 10.0,
    }
}

fn costs(park_seconds: f64, next_wake_seconds: f64, retained_host_bytes: u64) -> ParkCosts {
    ParkCosts {
        park_seconds,
        next_wake_seconds,
        retained_host_bytes,
        interrupted_requests_per_park: 0.0,
    }
}

#[test]
fn halving_eviction_while_doubling_the_next_wake_wins_only_for_low_reuse() {
    // Standard sleep parks in 2 s and wakes in 4 s; the clean drop halves the park and
    // doubles the wake. Expected cost: sleep 2 + 4p, clean drop 1 + 8p, equal at p = 1/4.
    let vllm = vllm_with_sleep();
    let eligible = eligibility_on(&vllm, &[], model_copy(), &allocations());
    let sleep = costs(2.0, 4.0, 0);
    let clean = costs(1.0, 8.0, 0);
    let candidates = [
        (ParkOption::SleepWithCpuCopy, sleep),
        (ParkOption::CleanDrop, clean),
    ];
    let low = choose_park(&candidates, &eligible, &policy(0.1)).unwrap();
    assert_eq!(low.option, ParkOption::CleanDrop);
    assert!((low.cost - 1.8).abs() < 1e-12);
    assert!((low.costs[0].1 - 2.4).abs() < 1e-12);
    let high = choose_park(&candidates, &eligible, &policy(0.5)).unwrap();
    assert_eq!(high.option, ParkOption::SleepWithCpuCopy);
    assert!((high.cost - 4.0).abs() < 1e-12);
    assert!((high.costs[1].1 - 5.0).abs() < 1e-12);
    let even = break_even_reuse(&clean, &sleep, &policy(0.0))
        .unwrap()
        .unwrap();
    assert!((even - 0.25).abs() < 1e-12);
    // At the break-even point both cost 3 s and the tie goes to the earlier option.
    let tie = choose_park(&candidates, &eligible, &policy(0.25)).unwrap();
    assert!((tie.costs[0].1 - tie.costs[1].1).abs() < 1e-12);
    assert_eq!(tie.option, ParkOption::SleepWithCpuCopy);
    // Pricing the pinned copy sleep keeps moves the balance toward the clean drop.
    let priced = ParkPolicy {
        weight_per_retained_host_byte_second: 1e-12,
        ..policy(0.5)
    };
    let with_memory = [
        (ParkOption::SleepWithCpuCopy, costs(2.0, 4.0, 8 * GB)),
        (ParkOption::CleanDrop, clean),
    ];
    assert_eq!(
        choose_park(&with_memory, &eligible, &priced)
            .unwrap()
            .option,
        ParkOption::CleanDrop
    );
    // An ineligible option is never chosen, however cheap.
    let ineligible = eligibility_on(&vllm, &[], model_copy(), &[]);
    assert_eq!(
        choose_park(&candidates, &ineligible, &policy(0.1))
            .unwrap()
            .option,
        ParkOption::SleepWithCpuCopy
    );
    assert!(lifecycle_cost(&clean, &policy(1.5)).is_err());
    assert!(lifecycle_cost(&costs(f64::NAN, 1.0, 0), &policy(0.5)).is_err());
    assert_eq!(
        break_even_reuse(&clean, &clean, &policy(0.0)).unwrap(),
        None
    );
}

fn parking_spec() -> ParkingSpec {
    ParkingSpec {
        parked: label("model-a"),
        other: label("model-b"),
        trials: 5,
        reuse_probabilities: vec![0.05, 0.25, 0.5, 0.75, 0.95],
        policy: policy(0.0),
        max_output_tokens: 8,
        tie_tolerance: 0.02,
        latency_objective: LatencyObjective {
            quantile: Quantile::P99,
            max_time_to_first_token_nanos: 10_000 * MILLIS,
        },
    }
}

#[test]
fn restart_sleep_and_clean_drop_are_compared_on_the_fake_runners() {
    let vllm = vllm_with_sleep();
    let eligible = eligibility_on(&vllm, &[], model_copy(), &allocations());
    let base = factory(profile(RunnerMode::FullProcessRestart), 7);
    let experiment = run_parking(&base, &eligible, &parking_spec()).unwrap();
    let close = |left: f64, right: f64| (left - right).abs() < 1e-9;
    let restart = experiment.measured(ParkOption::Restart).unwrap();
    let sleep = experiment.measured(ParkOption::SleepWithCpuCopy).unwrap();
    let clean = experiment.measured(ParkOption::CleanDrop).unwrap();
    assert_eq!(restart.mode, RunnerMode::FullProcessRestart);
    assert_eq!(sleep.mode, RunnerMode::VersionSupportedSleep);
    assert_eq!(clean.mode, RunnerMode::VerifiedReload);
    for measured in [restart, sleep, clean] {
        assert_eq!(measured.park_seconds.len(), 5);
        assert_eq!(measured.next_wake_seconds.len(), 5);
        assert_eq!(measured.interrupted_requests, 0);
        assert!(measured.measurement.provenance.is_fake_substrate());
        // Every option leaves the reclaimable page-cache copy of model-a's 8 GB behind.
        assert_eq!(measured.reclaimable_host_bytes, 8 * GB);
    }
    // Park latency: process exit, device-to-host sleep copy, and a drop with no copy.
    let park = |measured: &OptionMeasurement| measured.costs().park_seconds;
    let wake = |measured: &OptionMeasurement| measured.costs().next_wake_seconds;
    assert!(close(park(restart), 0.1));
    assert!(close(park(sleep), 0.35));
    assert!(close(park(clean), 0.05));
    // Next wake: startup 2.0 + warm load 0.4 + capture 0.3; the wake copy; warm load and
    // capture in the retained process.
    assert!(close(wake(restart), 2.7));
    assert!(close(wake(sleep), 0.35));
    assert!(close(wake(clean), 0.7));
    // Sleep keeps the parked process (2 GB) and its pinned 8 GB copy; the others keep none.
    assert_eq!(sleep.retained_host_bytes, 10 * GB);
    assert_eq!(restart.retained_host_bytes, 0);
    assert_eq!(clean.retained_host_bytes, 0);
    assert!(experiment.outcomes.iter().any(|outcome| matches!(
        outcome,
        OptionOutcome::NotRun { label, .. } if label == "clean-drop-reload-from-local-storage"
    )));
    // Clean drop 0.05 + 0.7p against min(sleep 0.35 + 0.35p, restart 0.1 + 2.7p): cheaper
    // until p = 6/7, so the claim narrows to low and middle reuse.
    let verdicts: Vec<(f64, CellVerdict)> = experiment
        .cells
        .iter()
        .map(|cell| (cell.reuse_probability, cell.verdict))
        .collect();
    assert_eq!(
        verdicts,
        vec![
            (0.05, CellVerdict::Better),
            (0.25, CellVerdict::Better),
            (0.5, CellVerdict::Better),
            (0.75, CellVerdict::Better),
            (0.95, CellVerdict::Worse)
        ]
    );
    let even = break_even_reuse(&clean.costs(), &sleep.costs(), &policy(0.0))
        .unwrap()
        .unwrap();
    assert!((even - 6.0 / 7.0).abs() < 1e-9);
    let claim = experiment.claim();
    assert_eq!(claim.evidence(), EvidenceClass::FakeSubstrate);
    assert_eq!(
        claim.outcome(),
        &ClaimOutcome::Narrowed {
            kept: vec![
                "reuse-0.05".to_string(),
                "reuse-0.25".to_string(),
                "reuse-0.50".to_string(),
                "reuse-0.75".to_string()
            ],
            dropped: vec!["reuse-0.95".to_string()]
        }
    );
}

#[test]
fn an_ineligible_clean_drop_is_not_run_and_backs_no_comparison() {
    let vllm = vllm_with_sleep();
    let ineligible = eligibility_on(&vllm, &[], model_copy(), &[]);
    let base = factory(profile(RunnerMode::FullProcessRestart), 7);
    let spec = ParkingSpec {
        trials: 1,
        ..parking_spec()
    };
    let experiment = run_parking(&base, &ineligible, &spec).unwrap();
    assert!(experiment.measured(ParkOption::CleanDrop).is_none());
    assert!(experiment.outcomes.iter().any(|outcome| matches!(
        outcome,
        OptionOutcome::NotEligible {
            option: ParkOption::CleanDrop,
            refusal: ParkRefusal::NoAllocations
        }
    )));
    assert!(experiment.cells.is_empty());
    assert_eq!(
        experiment.claim().outcome(),
        &ClaimOutcome::Inconclusive {
            reason: crate::model_memory::readiness::claim::InconclusiveReason::NoComparison
        }
    );
    let zero = ParkingSpec {
        trials: 0,
        ..parking_spec()
    };
    assert!(run_parking(&base, &ineligible, &zero).is_err());
}
