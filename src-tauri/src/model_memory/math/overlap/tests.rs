use super::*;
use crate::model_memory::math::test_support::SeededRng;

fn groups(arrivals: &[f64], compute: &[f64]) -> Vec<GroupTiming> {
    arrivals
        .iter()
        .zip(compute)
        .map(|(&usable_at_seconds, &compute_seconds)| GroupTiming {
            usable_at_seconds,
            compute_seconds,
        })
        .collect()
}

/// The mistaken per-group check of GPU §2.6: each group's own transfer time
/// (`a_i - a_(i-1)`, with `a_0 = 0`) fits within its own compute time. Test-only: it
/// is not a no-stall criterion.
fn local_comparison_passes(groups: &[GroupTiming]) -> bool {
    let mut previous = 0.0;
    groups.iter().all(|group| {
        let transfer = group.usable_at_seconds - previous;
        previous = group.usable_at_seconds;
        transfer <= group.compute_seconds
    })
}

#[test]
fn the_recurrence_gives_known_finish_times() {
    let plan = groups(&[0.5, 1.0, 4.0], &[1.0, 1.0, 1.0]);
    assert_eq!(finish_times(&plan).unwrap(), vec![1.5, 2.5, 5.0]);
    assert_eq!(ideal_finish_seconds(&plan).unwrap(), 3.5);
    assert_eq!(
        no_stall(&plan).unwrap(),
        NoStall::Stalls {
            group: 3,
            usable_at_seconds: 4.0,
            deadline_seconds: 2.5,
        }
    );
}

#[test]
fn the_counterexample_passes_the_local_check_yet_finishes_at_21_not_12() {
    let plan = groups(&[1.0, 11.0], &[1.0, 10.0]);
    assert!(local_comparison_passes(&plan));
    assert_eq!(finish_times(&plan).unwrap(), vec![2.0, 21.0]);
    assert_eq!(ideal_finish_seconds(&plan).unwrap(), 12.0);
    assert_eq!(
        no_stall(&plan).unwrap(),
        NoStall::Stalls {
            group: 2,
            usable_at_seconds: 11.0,
            deadline_seconds: 2.0,
        }
    );
}

#[test]
fn later_loads_hidden_behind_earlier_compute_reach_the_ideal() {
    let plan = groups(&[1.0, 2.0, 4.0], &[1.0, 2.0, 3.0]);
    assert_eq!(no_stall(&plan).unwrap(), NoStall::Holds);
    assert_eq!(finish_times(&plan).unwrap(), vec![2.0, 4.0, 7.0]);
    assert_eq!(ideal_finish_seconds(&plan).unwrap(), 7.0);
}

#[test]
fn the_no_stall_condition_matches_the_recurrence_on_random_schedules() {
    let mut rng = SeededRng::new(0x2_6);
    let mut stalled = 0;
    for _ in 0..2000 {
        let count = 1 + (rng.next_u64() % 8) as usize;
        let arrivals: Vec<f64> = (0..count).map(|_| rng.range(0.0, 10.0)).collect();
        let compute: Vec<f64> = (0..count).map(|_| rng.range(0.0, 3.0)).collect();
        let plan = groups(&arrivals, &compute);
        let last = *finish_times(&plan).unwrap().last().unwrap();
        let ideal = ideal_finish_seconds(&plan).unwrap();
        match no_stall(&plan).unwrap() {
            NoStall::Holds => assert_eq!(last, ideal),
            NoStall::Stalls { .. } => {
                stalled += 1;
                assert!(last > ideal);
            }
        }
    }
    assert!(stalled > 100 && stalled < 2000);
}

#[test]
fn overlap_inputs_are_validated() {
    assert_eq!(
        finish_times(&[]),
        Err(OverlapError::Input(InputError::Empty { field: "groups" }))
    );
    assert!(no_stall(&groups(&[f64::NAN], &[1.0])).is_err());
    assert!(ideal_finish_seconds(&groups(&[1.0], &[-1.0])).is_err());
}

fn layer(at: f64, compute_seconds: f64) -> GroupRequirement {
    GroupRequirement {
        weights_usable_at_seconds: at,
        compute_seconds,
        dependencies: Vec::new(),
    }
}

#[test]
fn the_first_token_waits_for_every_layer_and_the_output_head() {
    let layers = [layer(1.0, 1.0), layer(2.0, 1.0), layer(3.0, 1.0)];
    let late_head = first_token(&layers, &layer(30.0, 0.5)).unwrap();
    assert_eq!(late_head.layers_finish_seconds, 4.0);
    assert_eq!(late_head.first_token_seconds, 30.5);
    assert_eq!(
        late_head.critical_input,
        Some(CriticalInput {
            group: GroupRef::OutputHead,
            cause: WaitCause::Weights,
            usable_at_seconds: 30.0,
        })
    );

    // An early head still waits for the last layer.
    let early_head = first_token(&layers, &layer(2.0, 0.5)).unwrap();
    assert_eq!(early_head.first_token_seconds, 4.5);
    assert_eq!(
        early_head.critical_input.map(|input| input.group),
        Some(GroupRef::Layer(1))
    );

    // A late final layer delays the token even when the head is ready.
    let late_layer = [layer(1.0, 1.0), layer(2.0, 1.0), layer(20.0, 1.0)];
    let token = first_token(&late_layer, &layer(0.0, 0.5)).unwrap();
    assert_eq!(token.first_token_seconds, 21.5);
    assert_eq!(
        token.critical_input.map(|input| input.group),
        Some(GroupRef::Layer(3))
    );

    let ready = first_token(&[layer(0.0, 1.0)], &layer(0.0, 0.5)).unwrap();
    assert_eq!(ready.first_token_seconds, 1.5);
    assert_eq!(ready.critical_input, None);
    assert!(first_token(&[], &layer(0.0, 0.5)).is_err());
    assert!(first_token(&[layer(f64::NAN, 1.0)], &layer(0.0, 0.5)).is_err());
}

#[test]
fn extra_dependencies_delay_the_first_token() {
    let cases = [
        (DependencyKind::TiedEmbeddings, None),
        (DependencyKind::RecurrentState, Some(1)),
        (DependencyKind::NonPersistentBuffers, Some(0)),
        (DependencyKind::MultimodalEncoder, Some(0)),
        (DependencyKind::GraphCapture, Some(2)),
    ];
    for (kind, layer_index) in cases {
        let mut layers = vec![layer(1.0, 1.0), layer(2.0, 1.0), layer(3.0, 1.0)];
        let mut head = layer(3.5, 0.5);
        let dependency = Dependency {
            kind,
            usable_at_seconds: 50.0,
        };
        let group = match layer_index {
            Some(index) => {
                layers[index].dependencies.push(dependency);
                GroupRef::Layer(index + 1)
            }
            None => {
                head.dependencies.push(dependency);
                GroupRef::OutputHead
            }
        };
        let token = first_token(&layers, &head).unwrap();
        let compute_after: f64 = match layer_index {
            Some(index) => {
                layers[index..]
                    .iter()
                    .map(|g| g.compute_seconds)
                    .sum::<f64>()
                    + 0.5
            }
            None => 0.5,
        };
        assert_eq!(token.first_token_seconds, 50.0 + compute_after, "{kind:?}");
        assert_eq!(
            token.critical_input,
            Some(CriticalInput {
                group,
                cause: WaitCause::Dependency(kind),
                usable_at_seconds: 50.0,
            })
        );
    }
    let mut head = layer(0.0, 0.5);
    head.dependencies.push(Dependency {
        kind: DependencyKind::GraphCapture,
        usable_at_seconds: -1.0,
    });
    assert!(first_token(&[layer(0.0, 1.0)], &head).is_err());
}

fn expert(layer: u32, expert: u32) -> ExpertId {
    ExpertId { layer, expert }
}

#[test]
fn an_moe_miss_loads_the_exact_expert_and_stalls() {
    let mut cache = ExpertCache::new();
    for (index, at) in [(1, 10.0), (4, 9.0), (6, 9.5)] {
        cache.insert(expert(0, index), at).unwrap();
    }
    let mut step = MoeStep::new(&[expert(0, 1), expert(0, 5)]).unwrap();
    let loads = step.resolve(&cache);
    // Experts 4 and 6 are resident, but only expert 5 satisfies the miss.
    assert_eq!(loads.len(), 1);
    assert_eq!(loads[0].expert(), expert(0, 5));
    assert_eq!(step.missing(), vec![expert(0, 5)]);
    assert_eq!(
        step.start_seconds(10.0),
        Err(OverlapError::MissingExperts {
            experts: vec![expert(0, 5)]
        })
    );

    let handle = cache.complete_load(loads[0], 10.2).unwrap();
    assert_eq!(handle.expert(), expert(0, 5));
    assert_eq!(handle.usable_at_seconds(), 10.2);
    step.bind(handle).unwrap();
    let start = step.start_seconds(10.0).unwrap();
    assert_eq!(start, 10.2);
    assert!(start - 10.0 > 0.0, "the miss stalls the step");
    assert!(step.missing().is_empty());
    assert_eq!(
        cache.lookup(expert(0, 5)).map(|h| h.expert()),
        Ok(expert(0, 5))
    );
}

#[test]
fn the_moe_api_refuses_substitute_experts() {
    let mut cache = ExpertCache::new();
    cache.insert(expert(0, 2), 0.0).unwrap();
    cache.insert(expert(1, 5), 0.0).unwrap();
    let mut step = MoeStep::new(&[expert(0, 5)]).unwrap();
    assert_eq!(step.resolve(&cache).len(), 1);

    let same_layer_other_expert = cache.lookup(expert(0, 2)).unwrap();
    assert_eq!(
        step.bind(same_layer_other_expert),
        Err(OverlapError::ExpertNotRequired {
            expert: expert(0, 2)
        })
    );
    let same_number_other_layer = cache.lookup(expert(1, 5)).unwrap();
    assert_eq!(
        step.bind(same_number_other_layer),
        Err(OverlapError::ExpertNotRequired {
            expert: expert(1, 5)
        })
    );
    assert!(step.start_seconds(0.0).is_err());

    let load = cache.lookup(expert(0, 5)).unwrap_err();
    let handle = cache.complete_load(load, 1.0).unwrap();
    step.bind(handle).unwrap();
    assert_eq!(
        step.bind(handle),
        Err(OverlapError::ExpertAlreadyBound {
            expert: expert(0, 5)
        })
    );
    assert_eq!(step.start_seconds(0.0), Ok(1.0));

    assert!(MoeStep::new(&[]).is_err());
    assert!(MoeStep::new(&[expert(0, 1), expert(0, 1)]).is_err());
    assert!(cache.insert(expert(0, 9), f64::INFINITY).is_err());
    assert!(step.start_seconds(-1.0).is_err());
}

#[test]
fn one_step_of_the_recurrence_matches_finish_times() {
    let group = |usable_at_seconds: f64, compute_seconds: f64| GroupTiming {
        usable_at_seconds,
        compute_seconds,
    };
    assert_eq!(finish_after(0.0, group(1.0, 1.0)), Ok(2.0));
    assert_eq!(finish_after(2.0, group(11.0, 10.0)), Ok(21.0));
    // A group already usable waits only for its predecessor.
    assert_eq!(finish_after(5.0, group(1.0, 0.5)), Ok(5.5));
    let mut rng = SeededRng::new(0x13);
    for _ in 0..200 {
        let count = 1 + (rng.next_u64() % 6) as usize;
        let plan: Vec<GroupTiming> = (0..count)
            .map(|_| group(rng.range(0.0, 10.0), rng.range(0.0, 3.0)))
            .collect();
        let mut finish = 0.0;
        let stepwise: Vec<f64> = plan
            .iter()
            .map(|timing| {
                finish = finish_after(finish, *timing).unwrap();
                finish
            })
            .collect();
        assert_eq!(stepwise, finish_times(&plan).unwrap());
    }
    assert!(finish_after(-1.0, group(0.0, 0.0)).is_err());
    assert!(finish_after(0.0, group(f64::NAN, 0.0)).is_err());
    assert!(finish_after(0.0, group(0.0, -1.0)).is_err());
}

#[test]
fn an_evicted_expert_must_be_loaded_again_before_its_step_starts() {
    let mut cache = ExpertCache::new();
    cache.insert(expert(0, 1), 0.0).unwrap();
    cache.insert(expert(0, 2), 0.0).unwrap();
    let mut step = MoeStep::new(&[expert(0, 1), expert(0, 2)]).unwrap();
    assert!(step.resolve(&cache).is_empty());
    assert_eq!(step.start_seconds_in(&cache, 1.0), Ok(1.0));

    // Evicted after binding: the checked start refuses and names the exact expert.
    assert!(cache.evict(expert(0, 2)));
    assert!(!cache.evict(expert(0, 2)));
    assert_eq!(
        step.start_seconds_in(&cache, 1.0),
        Err(OverlapError::MissingExperts {
            experts: vec![expert(0, 2)]
        })
    );
    assert!(cache.lookup(expert(0, 2)).is_err());
    // Resolving again issues the exact load; no other expert stands in.
    let loads = step.resolve(&cache);
    assert_eq!(
        loads.iter().map(|load| load.expert()).collect::<Vec<_>>(),
        vec![expert(0, 2)]
    );
    let handle = cache.complete_load(loads[0], 1.5).unwrap();
    step.bind(handle).unwrap();
    assert_eq!(step.start_seconds_in(&cache, 1.0), Ok(1.5));

    // A handle taken before an eviction and re-insert is stale: the step waits for the
    // fresh entry instead.
    let stale = cache.lookup(expert(0, 1)).unwrap();
    assert!(cache.evict(expert(0, 1)));
    cache.insert(expert(0, 1), 3.0).unwrap();
    let mut other = MoeStep::new(&[expert(0, 1)]).unwrap();
    other.bind(stale).unwrap();
    assert!(other.start_seconds_in(&cache, 0.0).is_err());
    assert!(other.resolve(&cache).is_empty());
    assert_eq!(other.start_seconds_in(&cache, 0.0), Ok(3.0));
    // The unchecked start keeps its meaning for a cache that never evicts.
    assert_eq!(step.start_seconds(1.0), Ok(1.5));

    let mut exhausted = ExpertCache {
        held: std::collections::BTreeMap::new(),
        next_residency: u64::MAX,
    };
    assert!(exhausted.insert(expert(0, 0), 0.0).is_err());
}
