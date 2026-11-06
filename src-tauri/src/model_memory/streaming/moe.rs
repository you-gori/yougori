//! Exact MoE expert dependencies and expert locality from traces (GPU §2.6 line 434, §4.4
//! line 695, §4.11 line 766).
//!
//! A [`RoutingTrace`] records which experts each step selected in each layer. Prefill
//! routing for streaming comes from it ([`routing_from_trace`]), and expert locality and
//! miss rate are replayed from it ([`replay_trace`]) — never derived from the router's
//! top-k: sparse routing per step does not mean sparse total residency. Every miss loads
//! exactly the routed expert through [`ExpertCache`] and [`MoeStep`], so a step stalls
//! until that expert is bound and no other expert stands in. One persistent cache serves the
//! whole replay; the least recently used expert of a layer is evicted from it with
//! [`ExpertCache::evict`], and a step starts only on experts the cache still holds
//! ([`MoeStep::start_seconds_in`]).

use std::collections::{BTreeMap, BTreeSet};
use std::ops::Range;

use crate::foundation::report::Ratio;
use crate::model_memory::math::overlap::{ExactExpertLoad, ExpertCache, ExpertId, MoeStep};

use super::architecture::{PrefillRouting, StreamingModel};
use super::deadline::ReadCostModel;
use super::window::ExactOp;
use super::StreamingError;

/// The experts each step selected in each layer, as recorded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RoutingTrace {
    layers: u32,
    experts_per_layer: u32,
    steps: Vec<Vec<BTreeSet<u32>>>,
}

impl RoutingTrace {
    /// Refuses an empty trace: locality is measured, never assumed (§4.11 line 766).
    pub fn new(
        layers: u32,
        experts_per_layer: u32,
        steps: Vec<Vec<BTreeSet<u32>>>,
    ) -> Result<Self, StreamingError> {
        if steps.is_empty() || layers == 0 || experts_per_layer == 0 {
            return Err(StreamingError::EmptyTrace);
        }
        for step in &steps {
            if step.len() != layers as usize {
                return Err(StreamingError::Invalid {
                    field: "RoutingTrace",
                    reason: "every step routes every layer",
                });
            }
            for selected in step {
                if selected.is_empty() || selected.iter().any(|e| *e >= experts_per_layer) {
                    return Err(StreamingError::Invalid {
                        field: "RoutingTrace",
                        reason: "every layer selects at least one existing expert",
                    });
                }
            }
        }
        Ok(Self {
            layers,
            experts_per_layer,
            steps,
        })
    }

    /// The number of recorded steps.
    pub fn steps(&self) -> usize {
        self.steps.len()
    }

    /// The mean fraction of a layer's experts one step selects: what sparse routing
    /// suggests, reported beside the measured locality and never used in its place.
    pub fn mean_selected_fraction(&self) -> f64 {
        let selected: usize = self.steps.iter().flatten().map(BTreeSet::len).sum();
        let lookups = self.steps.len() as f64 * f64::from(self.layers);
        selected as f64 / (lookups * f64::from(self.experts_per_layer))
    }
}

/// An LRU expert cache per layer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExpertCacheConfig {
    pub capacity_per_layer: u32,
}

/// Locality and miss rate measured from a trace.
#[derive(Clone, Debug, PartialEq)]
pub struct ExpertLocality {
    pub lookups: u64,
    pub hits: u64,
    pub misses: u64,
    /// Misses over lookups, with both counts.
    pub miss_rate: Ratio,
    pub distinct_experts_touched: u64,
    pub total_experts: u64,
    pub mean_selected_fraction: f64,
    /// Seconds steps waited for exact expert loads.
    pub stall_seconds: f64,
    pub missed_bytes: u64,
}

/// Binds every routed expert of one layer step that `cache` holds and returns the exact
/// loads the misses need (§2.6 line 434).
pub fn resolve_layer(
    cache: &ExpertCache,
    layer: u32,
    routed: &BTreeSet<u32>,
) -> Result<(MoeStep, Vec<ExactExpertLoad>), StreamingError> {
    let required: Vec<ExpertId> = routed
        .iter()
        .map(|expert| ExpertId {
            layer,
            expert: *expert,
        })
        .collect();
    let mut step = MoeStep::new(&required)?;
    let loads = step.resolve(cache);
    Ok((step, loads))
}

/// Replays a trace through per-layer LRU caches.
pub fn replay_trace(
    trace: &RoutingTrace,
    config: ExpertCacheConfig,
    expert_bytes: u64,
    cost: &ReadCostModel,
) -> Result<ExpertLocality, StreamingError> {
    let largest_step = trace
        .steps
        .iter()
        .flatten()
        .map(BTreeSet::len)
        .max()
        .unwrap_or(0);
    if (config.capacity_per_layer as usize) < largest_step {
        return Err(StreamingError::Invalid {
            field: "capacity_per_layer",
            reason: "the cache cannot hold one step's routed experts",
        });
    }
    let mut cache = ExpertCache::new();
    // Per layer, the experts the cache holds, most recently used last.
    let mut recency: Vec<Vec<u32>> = vec![Vec::new(); trace.layers as usize];
    let mut touched: BTreeSet<(u32, u32)> = BTreeSet::new();
    let (mut lookups, mut misses) = (0u64, 0u64);
    let mut stall_seconds = 0.0;
    let mut now = 0.0;
    let load_seconds = cost.read_seconds(expert_bytes, 1);
    for step in &trace.steps {
        for (layer_index, routed) in step.iter().enumerate() {
            let layer = layer_index as u32;
            let (mut moe_step, loads) = resolve_layer(&cache, layer, routed)?;
            let mut at = now;
            for load in &loads {
                at += load_seconds;
                let handle = cache.complete_load(*load, at)?;
                moe_step.bind(handle)?;
            }
            // Every routed expert is bound and held: the step starts once its loads finish.
            let start = moe_step.start_seconds_in(&cache, now)?;
            stall_seconds += start - now;
            now = start;
            lookups += routed.len() as u64;
            misses += loads.len() as u64;
            let order = recency
                .get_mut(layer_index)
                .ok_or(StreamingError::Unknown {
                    field: "RoutingTrace layers",
                    index: layer_index,
                })?;
            for expert in routed {
                touched.insert((layer, *expert));
                order.retain(|held| held != expert);
                order.push(*expert);
            }
            while order.len() > config.capacity_per_layer as usize {
                let victim = order.remove(0);
                if !cache.evict(ExpertId {
                    layer,
                    expert: victim,
                }) {
                    return Err(StreamingError::Invalid {
                        field: "expert cache",
                        reason: "the recency list names an expert the cache does not hold",
                    });
                }
            }
        }
    }
    let total_experts = u64::from(trace.layers) * u64::from(trace.experts_per_layer);
    Ok(ExpertLocality {
        lookups,
        hits: lookups - misses,
        misses,
        miss_rate: Ratio::new(misses, lookups)?,
        distinct_experts_touched: touched.len() as u64,
        total_experts,
        mean_selected_fraction: trace.mean_selected_fraction(),
        stall_seconds,
        missed_bytes: misses.saturating_mul(expert_bytes),
    })
}

/// The expert sets a memory-limited window streams (§4.11): one exact operation per step
/// and layer, reading the layer's shared tensor and exactly the routed experts. Tensor
/// `l` is layer `l`'s shared tensor and tensor `layers + l × experts + e` its expert `e`;
/// the first value is the tensor count.
pub fn expert_set_ops(
    trace: &RoutingTrace,
    compute_seconds: f64,
) -> Result<(usize, Vec<ExactOp>), StreamingError> {
    let compute_seconds = super::non_negative("compute_seconds", compute_seconds)?;
    let layers = trace.layers as usize;
    let experts = trace.experts_per_layer as usize;
    let tensors = layers
        .checked_mul(experts)
        .and_then(|routed| routed.checked_add(layers))
        .ok_or(StreamingError::Invalid {
            field: "RoutingTrace",
            reason: "too many experts",
        })?;
    let ops = trace
        .steps
        .iter()
        .flat_map(|step| {
            step.iter().enumerate().map(move |(layer, routed)| ExactOp {
                reads: std::iter::once(layer)
                    .chain(
                        routed
                            .iter()
                            .map(move |e| layers + layer * experts + *e as usize),
                    )
                    .collect(),
                compute_seconds,
                output_activation_bytes: 0,
            })
        })
        .collect();
    Ok((tensors, ops))
}

/// The exact experts a prefill over `steps` of the trace routes to, as tensors of
/// `model` (§4.4: an MoE adapter with explicit expert dependencies).
pub fn routing_from_trace(
    model: &StreamingModel,
    trace: &RoutingTrace,
    steps: Range<usize>,
) -> Result<PrefillRouting, StreamingError> {
    let selected = trace
        .steps
        .get(steps.clone())
        .filter(|s| !s.is_empty())
        .ok_or(StreamingError::Invalid {
            field: "steps",
            reason: "the prefill covers at least one recorded step",
        })?;
    let by_expert: BTreeMap<ExpertId, usize> = model
        .tensors()
        .iter()
        .enumerate()
        .filter_map(|(index, tensor)| tensor.expert.map(|expert| (expert, index)))
        .collect();
    let mut routing = PrefillRouting::new();
    for (index, group) in model.groups().iter().enumerate() {
        let Some(layer) = group
            .experts
            .first()
            .and_then(|tensor| model.tensors().get(*tensor))
            .and_then(|tensor| tensor.expert)
            .map(|expert| expert.layer)
        else {
            continue;
        };
        let mut tensors = BTreeSet::new();
        for step in selected {
            let routed = step.get(layer as usize).ok_or(StreamingError::Routing {
                group: index,
                reason: "the trace has no routing for this layer",
            })?;
            for expert in routed {
                let tensor = by_expert
                    .get(&ExpertId {
                        layer,
                        expert: *expert,
                    })
                    .ok_or(StreamingError::Routing {
                        group: index,
                        reason: "the trace routes to an expert the model does not store",
                    })?;
                tensors.insert(*tensor);
            }
        }
        routing = routing.route(index, tensors);
    }
    Ok(routing)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model_memory::bench::rng::SeededRng;
    use crate::model_memory::math::overlap::OverlapError;
    use crate::model_memory::streaming::test_support::*;

    fn trace(layers: u32, experts: u32, steps: Vec<Vec<Vec<u32>>>) -> RoutingTrace {
        RoutingTrace::new(
            layers,
            experts,
            steps
                .into_iter()
                .map(|step| step.into_iter().map(|s| s.into_iter().collect()).collect())
                .collect(),
        )
        .unwrap()
    }

    #[test]
    fn miss_rate_comes_from_the_trace() {
        // One layer, eight experts, top-2, a cache of two experts. Steps: {0,1} {0,1}
        // {2,3} {0,1}: lookups 8, misses 2 + 0 + 2 + 2 = 6.
        let recorded = trace(
            1,
            8,
            vec![
                vec![vec![0, 1]],
                vec![vec![0, 1]],
                vec![vec![2, 3]],
                vec![vec![0, 1]],
            ],
        );
        let path = read_path(0.001, 1e9);
        let locality = replay_trace(
            &recorded,
            ExpertCacheConfig {
                capacity_per_layer: 2,
            },
            100_000_000,
            &path,
        )
        .unwrap();
        assert_eq!(
            (locality.lookups, locality.misses, locality.hits),
            (8, 6, 2)
        );
        assert_eq!(locality.miss_rate.numerator(), 6);
        assert_eq!(locality.miss_rate.denominator(), 8);
        assert_eq!(locality.distinct_experts_touched, 4);
        assert_eq!(locality.missed_bytes, 600_000_000);
        // Each miss loads exactly one 100 MB expert: 0.101 s; misses come in pairs.
        assert!((locality.stall_seconds - 3.0 * 0.202).abs() < 1e-9);
        // Sparse routing suggests a quarter of the experts per step...
        assert!((locality.mean_selected_fraction - 0.25).abs() < 1e-12);
    }

    #[test]
    fn sparse_routing_does_not_mean_sparse_total_residency() {
        // Top-2 of 8 in every step, but a uniform router touches all 8 within a few
        // steps, and a 2-expert cache misses most lookups; a skewed router hits.
        let mut rng = SeededRng::new(11);
        let uniform: Vec<Vec<Vec<u32>>> = (0..64)
            .map(|_| {
                let first = rng.below(8) as u32;
                let second = (first + 1 + rng.below(7) as u32) % 8;
                vec![vec![first, second]]
            })
            .collect();
        let skewed: Vec<Vec<Vec<u32>>> = (0..64)
            .map(|step| {
                vec![if step % 16 == 15 {
                    vec![0, 5]
                } else {
                    vec![0, 1]
                }]
            })
            .collect();
        let path = read_path(0.0, 1e9);
        let config = ExpertCacheConfig {
            capacity_per_layer: 2,
        };
        let uniform = replay_trace(&trace(1, 8, uniform), config, 1_000, &path).unwrap();
        let skewed = replay_trace(&trace(1, 8, skewed), config, 1_000, &path).unwrap();
        assert_eq!(
            uniform.mean_selected_fraction,
            skewed.mean_selected_fraction
        );
        assert_eq!(uniform.distinct_experts_touched, 8);
        let rate = |l: &ExpertLocality| l.miss_rate.value().value().unwrap();
        assert!(rate(&uniform) > 0.5);
        assert!(rate(&skewed) < 0.1);
        // No trace, no locality.
        assert_eq!(
            RoutingTrace::new(1, 8, vec![]),
            Err(StreamingError::EmptyTrace)
        );
        assert!(replay_trace(
            &trace(1, 8, vec![vec![vec![0, 1, 2]]]),
            config,
            1_000,
            &path
        )
        .is_err());
    }

    #[test]
    fn a_predicted_expert_never_stands_in_for_the_routed_one() {
        // Expert 1 of layer 0 was prefetched on a prediction; the router chose expert 2.
        let mut cache = ExpertCache::new();
        cache
            .insert(
                ExpertId {
                    layer: 0,
                    expert: 1,
                },
                0.0,
            )
            .unwrap();
        let (mut step, loads) = resolve_layer(&cache, 0, &[2].into_iter().collect()).unwrap();
        assert_eq!(loads.len(), 1);
        assert_eq!(
            loads[0].expert(),
            ExpertId {
                layer: 0,
                expert: 2
            }
        );
        // The step cannot start, and the prefetched expert cannot be bound instead.
        assert!(matches!(
            step.start_seconds(0.0),
            Err(OverlapError::MissingExperts { .. })
        ));
        let wrong = cache
            .lookup(ExpertId {
                layer: 0,
                expert: 1,
            })
            .unwrap();
        assert!(matches!(
            step.bind(wrong),
            Err(OverlapError::ExpertNotRequired { .. })
        ));
        let exact = cache.complete_load(loads[0], 0.25).unwrap();
        step.bind(exact).unwrap();
        assert_eq!(step.start_seconds_in(&cache, 0.1), Ok(0.25));
        // Evicted after binding: the step no longer starts on it and must load it again.
        assert!(cache.evict(ExpertId {
            layer: 0,
            expert: 2
        }));
        assert!(matches!(
            step.start_seconds_in(&cache, 0.1),
            Err(OverlapError::MissingExperts { .. })
        ));
        assert_eq!(step.resolve(&cache).len(), 1);
    }

    #[test]
    fn a_window_streams_exact_expert_sets_and_locality_sets_its_traffic() {
        use crate::model_memory::residency::Capacity;
        use crate::model_memory::streaming::window::{
            best_window, oracle, WindowBudget, WindowProblem,
        };
        // One layer, eight 1 GB experts, top-2, a 5 GB device: the shared tensor and
        // two expert sets fit beside each other.
        let steps = |pairs: &[[u32; 2]]| -> Vec<Vec<Vec<u32>>> {
            pairs.iter().map(|pair| vec![pair.to_vec()]).collect()
        };
        let skewed = trace(
            1,
            8,
            steps(&[[0, 1], [0, 1], [0, 1], [0, 2], [0, 1], [0, 1]]),
        );
        let spread = trace(
            1,
            8,
            steps(&[[0, 1], [2, 3], [4, 5], [6, 7], [1, 2], [3, 4]]),
        );
        let budget = WindowBudget::from_capacity(Capacity::Physical { bytes: 5 * GB }, 0).unwrap();
        let path = read_path(0.0, 25e9);
        let moved = |recorded: &RoutingTrace| {
            let (tensors, ops) = expert_set_ops(recorded, 0.02).unwrap();
            let problem = WindowProblem::new(vec![GB; tensors], ops, budget, path).unwrap();
            let (_, plan, window) = best_window(&problem, 2).unwrap();
            let (_, best) = oracle(&problem).unwrap();
            assert!(best.finish_seconds <= window.finish_seconds + 1e-9);
            // Only routed experts are ever resident.
            for (set, op) in plan.sets.iter().zip(problem.ops()) {
                assert!(op.reads.iter().all(|tensor| set.contains(tensor)));
            }
            window.transferred_bytes
        };
        // Same top-2 sparsity, very different traffic: locality is measured.
        assert!(moved(&skewed) < moved(&spread));
        assert_eq!(
            skewed.mean_selected_fraction(),
            spread.mean_selected_fraction()
        );
    }

    #[test]
    fn prefill_routing_comes_from_the_trace() {
        let model = StreamingModel::new(moe_spec(2, 4, MIB)).unwrap();
        let recorded = trace(
            2,
            4,
            vec![
                vec![vec![0], vec![3]],
                vec![vec![1], vec![3]],
                vec![vec![2], vec![2]],
            ],
        );
        let routing = routing_from_trace(&model, &recorded, 0..2).unwrap();
        let layer0 = &model.groups()[1].experts;
        let layer1 = &model.groups()[2].experts;
        assert_eq!(
            routing.experts(1),
            Some(&[layer0[0], layer0[1]].into_iter().collect())
        );
        assert_eq!(routing.experts(2), Some(&[layer1[3]].into_iter().collect()));
        assert!(routing_from_trace(&model, &recorded, 5..6).is_err());
        let too_many = trace(2, 9, vec![vec![vec![8], vec![0]]]);
        assert!(routing_from_trace(&model, &too_many, 0..1).is_err());
    }
}
