//! §4.8 temporary distributed execution: activation traffic, latency, microbatch fill,
//! temporary KV placement, and the window strategies, including the LAN that erases the
//! benefit.

use crate::model_memory::math::bounds::{BandwidthBasis, BandwidthRating};
use crate::model_memory::math::InputError;

use super::super::distributed::*;
use super::super::experiments::{two_stage_plan, window_for, window_shape, WINDOW_REGIMES};
use super::super::fixtures::SyntheticFleet;
use super::super::replication::NodeId;
use super::support::*;

fn fast_lan() -> PipelinePlan {
    two_stage_plan(1.25e9, 0.0002, 1.0).unwrap()
}

#[test]
fn activation_traffic_is_hidden_size_times_bytes_per_token_at_each_boundary() {
    let shape = window_shape();
    assert_eq!(shape.activation_bytes_per_token(), 8_192);
    assert_eq!(shape.boundary_bytes(2_048), Ok(16_777_216));
    assert!(shape.boundary_bytes(u64::MAX).is_err());
    // A 2,048-token prompt and 127 decode tokens after the first.
    assert_eq!(
        fast_lan().activation_traffic_bytes(2_048, 128).unwrap(),
        vec![2_175 * 8_192]
    );
}

#[test]
fn microbatch_fill_is_m_over_m_plus_p_minus_one() {
    assert_close(microbatch_fill(2, 1).unwrap(), 0.5);
    assert_close(microbatch_fill(2, 4).unwrap(), 0.8);
    assert_close(microbatch_fill(4, 4).unwrap(), 4.0 / 7.0);
    assert_eq!(
        microbatch_fill(2, 0),
        Err(InputError::NotPositive {
            field: "microbatches"
        })
    );
    assert!(microbatch_fill(0, 4).is_err());
}

#[test]
fn prefill_and_decode_pay_compute_link_latency_and_activation_bytes() {
    let plan = fast_lan();
    // One microbatch: 0.1 s + (0.2 ms + 16 MiB at 1.25 GB/s) + 0.1 s.
    assert_close(plan.prefill_seconds(2_048, 1).unwrap(), 0.2136217728);
    // Four microbatches of 512 tokens: 0.025 + 0.0035554432 + 0.025, then 3 × 0.025.
    assert_close(plan.prefill_seconds(2_048, 4).unwrap(), 0.1285554432);
    // Two 10 ms stages, one token's activations forward and the token id back.
    assert_close(plan.decode_step_seconds().unwrap(), 0.0204065568);
}

#[test]
fn temporary_kv_must_fit_every_stage() {
    let plan = fast_lan();
    // 2,176 tokens × 16 layers × 4,096 bytes per stage.
    assert_eq!(
        plan.kv_placement(&[2_176]).unwrap().stage_bytes,
        vec![142_606_336, 142_606_336]
    );
    assert_eq!(
        plan.kv_placement(&[70_000]),
        Err(DistributedError::KvDoesNotFit {
            stage: 0,
            needed_bytes: 70_000 * 65_536,
            free_bytes: 4 << 30,
        })
    );
}

#[test]
fn stages_must_hold_complementary_layers_over_measured_links() {
    let plan = fast_lan();
    let stages = plan.stages().to_vec();
    let link = PipelineLink {
        bandwidth: BandwidthRating::measured_directional(1.25e9).unwrap(),
        latency_seconds: 0.0002,
    };
    let mut gap = stages.clone();
    gap[1].first_layer = 17;
    gap[1].layer_count = 15;
    assert_eq!(
        PipelinePlan::new(window_shape(), gap, vec![link], link, 4),
        Err(DistributedError::LayersNotComplementary)
    );
    let mut short = stages.clone();
    short[1].layer_count = 14;
    assert_eq!(
        PipelinePlan::new(window_shape(), short, vec![link], link, 4),
        Err(DistributedError::LayersNotComplementary)
    );
    assert!(PipelinePlan::new(window_shape(), stages[..1].to_vec(), vec![], link, 4).is_err());
    assert!(PipelinePlan::new(window_shape(), stages.clone(), vec![], link, 4).is_err());
    let advertised = PipelineLink {
        bandwidth: BandwidthRating::advertised(1.25e9).unwrap(),
        latency_seconds: 0.0002,
    };
    assert_eq!(
        PipelinePlan::new(window_shape(), stages, vec![advertised], link, 4),
        Err(DistributedError::UnmeasuredLink {
            basis: BandwidthBasis::Advertised
        })
    );
    assert_eq!(NodeId::new("a").unwrap().as_str(), "a");
}

fn compare(index: usize) -> WindowComparison {
    let synthetic = SyntheticFleet::new().unwrap();
    let (plan, window, requests) =
        window_for(&synthetic, &WINDOW_REGIMES[index], 1.0, 1.0).unwrap();
    compare_window(
        &plan,
        &window,
        &requests,
        &synthetic.requested_single_or_pipeline().unwrap(),
        synthetic.epoch,
    )
    .unwrap()
}

fn served(comparison: &WindowComparison, strategy: WindowStrategy) -> &[WindowServed] {
    &comparison
        .strategies
        .iter()
        .find(|(candidate, _)| *candidate == strategy)
        .unwrap()
        .1
}

#[test]
fn on_a_fast_lan_with_an_overloaded_donor_the_pipeline_serves_while_replicas_load() {
    let comparison = compare(0);
    assert_eq!(
        comparison.best_by_worst_first_token(),
        Some(WindowStrategy::TemporaryPipeline)
    );
    let pipeline = served(&comparison, WindowStrategy::TemporaryPipeline);
    // The pipeline starts at 5 s; each request takes 0.1286 s of prefill and 127 decode
    // steps of 20.4 ms. Requests started before 15 s stay on the pipeline, even the one
    // that finishes after the replicas are ready; later ones go to the replicas.
    assert_close(
        pipeline[0].time_to_first_token_seconds(),
        5.0 + 0.1285554432 + 0.02,
    );
    let units: Vec<ServingUnit> = pipeline.iter().map(|entry| entry.unit).collect();
    assert_eq!(
        units,
        vec![
            ServingUnit::Pipeline,
            ServingUnit::Pipeline,
            ServingUnit::Pipeline,
            ServingUnit::Pipeline,
            ServingUnit::Replica(0),
            ServingUnit::Replica(1),
        ]
    );
    assert!(pipeline[3].start_seconds < 15.0 && pipeline[3].completion_seconds > 15.0);
    assert_eq!(
        pipeline[3].plan,
        Some(crate::foundation::ids::ModelActivationGeneration::new(1))
    );
    assert!(pipeline[0].activation_bytes > 0);
    // The overloaded donor starts nothing before the replicas: it is no better than
    // waiting.
    let donor = served(&comparison, WindowStrategy::RouteToDonor);
    assert!(donor
        .iter()
        .all(|entry| matches!(entry.unit, ServingUnit::Replica(_))));
}

#[test]
fn on_a_slow_lan_communication_erases_the_benefit() {
    let comparison = compare(1);
    assert_eq!(
        comparison.best_by_worst_first_token(),
        Some(WindowStrategy::WaitForReplicas)
    );
    let pipeline = served(&comparison, WindowStrategy::TemporaryPipeline);
    // Four 2,048-token microbatches each cross a 50 Mb/s link in 2.69 s: prefill takes
    // 10.96 s, so the first request waits longer than for the replicas at 6 s.
    let plan = two_stage_plan(6.25e6, 0.005, 1.0).unwrap();
    assert_close(plan.prefill_seconds(8_192, 4).unwrap(), 10.95741824);
    let wait = served(&comparison, WindowStrategy::WaitForReplicas);
    assert!(pipeline[0].time_to_first_token_seconds() > wait[0].time_to_first_token_seconds());
    assert_close(wait[0].time_to_first_token_seconds(), 6.0 + 0.8 + 0.02);
}

#[test]
fn an_idle_donor_beats_the_pipeline() {
    let comparison = compare(2);
    assert_eq!(
        comparison.best_by_worst_first_token(),
        Some(WindowStrategy::RouteToDonor)
    );
    let donor = served(&comparison, WindowStrategy::RouteToDonor);
    assert_eq!(donor[0].unit, ServingUnit::Donor);
    assert_eq!(donor[0].plan, None);
    // 0.2 s of prefill plus the client and donor network tails.
    assert_close(donor[0].time_to_first_token_seconds(), 0.2 + 0.02 + 0.01);
}

#[test]
fn the_donor_strategy_needs_a_donor_and_windows_are_checked() {
    let synthetic = SyntheticFleet::new().unwrap();
    let (plan, mut window, requests) =
        window_for(&synthetic, &WINDOW_REGIMES[0], 1.0, 1.0).unwrap();
    let model = synthetic.requested_single_or_pipeline().unwrap();
    window.donor = None;
    assert_eq!(
        serve_window(
            &plan,
            &window,
            &requests,
            WindowStrategy::RouteToDonor,
            &model,
            synthetic.epoch
        ),
        Err(DistributedError::NoDonor)
    );
    assert_eq!(
        compare_window(&plan, &window, &requests, &model, synthetic.epoch)
            .unwrap()
            .strategies
            .len(),
        2
    );
    let mut reversed = window;
    reversed.replica_generation = reversed.pipeline_generation;
    assert!(serve_window(
        &plan,
        &reversed,
        &requests,
        WindowStrategy::WaitForReplicas,
        &model,
        synthetic.epoch
    )
    .is_err());
    // A request that only accepts the single-GPU execution cannot be put on the pipeline:
    // the epoch replay refuses to publish it.
    let exact = synthetic.requested_single().unwrap();
    assert!(matches!(
        serve_window(
            &plan,
            &window,
            &requests,
            WindowStrategy::TemporaryPipeline,
            &exact,
            synthetic.epoch
        ),
        Err(DistributedError::Epoch(
            super::super::epochs::EpochRefusal::NotAccepted { .. }
        ))
    ));
}
