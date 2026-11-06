//! §4.6 joint routing: worked decisions, the exact-model and authorization rules, stale
//! reports, session moves by distinct mechanisms, locality, egress, donor impact and
//! hysteresis.

use crate::foundation::ids::{ExecutionCategory, ModelActivationGeneration, MonotonicTime};
use crate::model_memory::identity::{
    AdvertisementRefusal, Dtype, GrantRefusal, GrantedUse, KvRepresentation, KvReuseRefusal,
    KvScopeComponent, Quantization, ScopeEnforcement, VersionedName,
};
use crate::model_memory::math::bounds::BandwidthRating;
use crate::model_memory::math::recompute::{KvRecompute, RecomputeRefusal};

use super::super::error::RoutingError;
use super::super::estimate::{SecondsEstimate, StaleRefusal};
use super::super::joint::*;
use super::support::*;

fn router(min_gain_seconds: f64, min_gain_fraction: f64) -> JointRouter {
    JointRouter::new(policy(min_gain_seconds, min_gain_fraction)).unwrap()
}

#[test]
fn a_ready_but_overloaded_gpu_loses_to_a_cold_idle_gpu() {
    let world = World::new();
    // A: ready, 6.0 ± 1.0 s queue, 1.5 ± 0.1 s compute, 20 ms tail: 7.52 ± 1.1 → 8.62.
    // B: cold, 2.8 ± 0.28 s load (2 s bound), no queue: 4.32 ± 0.38 → 4.70.
    let endpoints = [
        world.ready("host-a", estimate(6.0, 1.0), estimate(1.5, 0.1)),
        world.cold("host-b", estimate(2.8, 0.28), estimate(1.5, 0.1)),
    ];
    let decision = router(0.25, 0.05)
        .route(
            &world.request(&["host-a", "host-b"], None),
            &endpoints,
            &world.clock,
        )
        .unwrap();
    assert_eq!(decision.chosen.device, world.gpu("host-b"));
    assert!(matches!(
        decision.chosen.authority,
        RouteAuthority::PreparedFromLocalArtifact { .. }
    ));
    let [cold, ready] = [&decision.options[0], &decision.options[1]];
    assert_close(cold.finish.finish.expected_seconds(), 4.32);
    assert_close(cold.score_seconds, 4.70);
    assert_close(ready.finish.finish.expected_seconds(), 7.52);
    assert_close(ready.score_seconds, 8.62);
}

#[test]
fn a_lightly_loaded_ready_gpu_beats_a_cold_load() {
    let world = World::new();
    let endpoints = [
        world.ready("host-a", estimate(1.0, 0.1), estimate(1.5, 0.1)),
        world.cold("host-b", estimate(2.8, 0.28), estimate(1.5, 0.1)),
    ];
    let decision = router(0.25, 0.05)
        .route(
            &world.request(&["host-a", "host-b"], None),
            &endpoints,
            &world.clock,
        )
        .unwrap();
    assert_eq!(decision.chosen.device, world.gpu("host-a"));
    assert_close(decision.chosen.score_seconds, 2.72);
    assert!(matches!(
        decision.chosen.authority,
        RouteAuthority::Ready(_)
    ));
}

#[test]
fn a_preparation_faster_than_the_physical_bound_is_refused() {
    let world = World::new();
    // 14 GB at 7 GB/s needs at least 2 s (§2.2); a 1.5 s claim cannot be compared.
    let fast = world.cold("host-b", estimate(1.5, 0.0), estimate(1.5, 0.0));
    let (options, ineligible) = router(0.25, 0.05)
        .evaluate(&world.request(&["host-b"], None), &[fast], &world.clock)
        .unwrap();
    assert!(options.is_empty());
    assert_eq!(
        ineligible[0].reason,
        Ineligible::BelowPhysicalBound {
            claimed_seconds: 1.5,
            lower_bound_seconds: 2.0
        }
    );
    // Over a measured 25 GB/s path the same bytes need 0.56 s (§2.2), so 0.56 s passes
    // and 0.5 s does not (the 0.8 s engine start is not part of this path).
    let mut at_25 = world.cold("host-b", estimate(0.56, 0.0), estimate(1.5, 0.0));
    if let EndpointState::Cold { preparation, .. } = &mut at_25.state {
        *preparation = nvme_preparation("host-b", estimate(0.56, 0.0), 25.0e9);
        preparation.minimum_seconds = 0.0;
    }
    let (options, _) = router(0.25, 0.05)
        .evaluate(
            &world.request(&["host-b"], None),
            &[at_25.clone()],
            &world.clock,
        )
        .unwrap();
    assert_eq!(options.len(), 1);
    if let EndpointState::Cold { preparation, .. } = &mut at_25.state {
        preparation.critical_path = estimate(0.5, 0.0);
    }
    let (_, ineligible) = router(0.25, 0.05)
        .evaluate(&world.request(&["host-b"], None), &[at_25], &world.clock)
        .unwrap();
    assert!(matches!(
        ineligible[0].reason,
        Ineligible::BelowPhysicalBound { .. }
    ));
}

#[test]
fn a_stale_report_is_penalized_and_a_too_old_one_is_not_compared() {
    let world = World::new();
    let mut aging = world.ready("host-a", estimate(1.0, 0.1), estimate(1.5, 0.1));
    aging.observed_at = seconds_ago(2.0);
    let (options, _) = router(0.25, 0.05)
        .evaluate(
            &world.request(&["host-a"], None),
            &[aging.clone()],
            &world.clock,
        )
        .unwrap();
    // 0.2 s penalty and 0.2 s more queue spread: 2.52 ± 0.4 + 0.2 = 3.12.
    assert_close(options[0].stale.penalty_seconds, 0.2);
    assert_close(options[0].finish.finish.uncertainty_seconds(), 0.4);
    assert_close(options[0].score_seconds, 3.12);
    aging.observed_at = seconds_ago(5.0);
    let (options, ineligible) = router(0.25, 0.05)
        .evaluate(&world.request(&["host-a"], None), &[aging], &world.clock)
        .unwrap();
    assert!(options.is_empty());
    assert!(matches!(
        ineligible[0].reason,
        Ineligible::StaleReport(StaleRefusal::TooOld { .. })
    ));
}

#[test]
fn advertisements_are_rechecked_before_serving() {
    let world = World::new();
    let request = world.request(&["host-a"], None);
    let evaluate = |endpoint: EndpointReport| {
        router(0.25, 0.05)
            .evaluate(&request, &[endpoint], &world.clock)
            .unwrap()
            .1
            .remove(0)
            .reason
    };
    let base = world.ready("host-a", estimate(1.0, 0.0), estimate(1.0, 0.0));
    let EndpointState::Ready(claim) = &base.state else {
        unreachable!("a ready endpoint");
    };

    // Expired.
    let mut expired = base.clone();
    let mut stale_claim = claim.clone();
    stale_claim.advertisement.expires_at = NOW;
    expired.state = EndpointState::Ready(stale_claim);
    assert!(matches!(
        evaluate(expired),
        Ineligible::Advertisement(AdvertisementRefusal::Expired { .. })
    ));

    // The authority already activated generation 2.
    let mut superseded = base.clone();
    let mut old_claim = claim.clone();
    old_claim.current.generation = ModelActivationGeneration::new(2);
    superseded.state = EndpointState::Ready(old_claim);
    assert!(matches!(
        evaluate(superseded),
        Ineligible::Advertisement(AdvertisementRefusal::OlderGeneration { .. })
    ));

    // An advertisement is never authority: no grant, no serving.
    let mut ungranted = base.clone();
    let mut bare_claim = claim.clone();
    bare_claim.grant = None;
    ungranted.state = EndpointState::Ready(bare_claim);
    assert_eq!(
        evaluate(ungranted),
        Ineligible::Advertisement(AdvertisementRefusal::Unauthorized(GrantRefusal::Missing))
    );

    // The report names another device than its residency.
    let mut moved = base;
    moved.device = world.gpu("host-z");
    let mut wide = request.clone();
    wide.authorized_machines.insert(world.gpu("host-z").machine);
    let reason = router(0.25, 0.05)
        .evaluate(&wide, &[moved], &world.clock)
        .unwrap()
        .1
        .remove(0)
        .reason;
    assert_eq!(reason, Ineligible::ReportDisagreesWithResidency);
}

#[test]
fn only_authorized_machines_inside_the_users_restrictions_are_compared() {
    let world = World::new();
    let endpoint = world.ready("host-a", estimate(1.0, 0.0), estimate(1.0, 0.0));
    let refuse = |request: &RoutingRequest| {
        router(0.25, 0.05)
            .route(request, &[endpoint.clone()], &world.clock)
            .unwrap_err()
    };
    let unauthorized = world.request(&["host-b"], None);
    assert_eq!(
        refuse(&unauthorized),
        RouteRefusal::NoEligibleEndpoint {
            ineligible: vec![IneligibleEndpoint {
                device: world.gpu("host-a"),
                reason: Ineligible::MachineNotAuthorized
            }]
        }
    );
    let mut excluded = world.request(&["host-a"], None);
    excluded
        .restrictions
        .excluded_machines
        .insert(world.gpu("host-a").machine);
    assert!(matches!(
        refuse(&excluded),
        RouteRefusal::NoEligibleEndpoint { ineligible } if ineligible[0].reason == Ineligible::ExcludedByUser
    ));
    let mut vm_only = world.request(&["host-a"], None);
    vm_only.restrictions.categories = [ExecutionCategory::VmSandbox].into_iter().collect();
    assert!(matches!(
        refuse(&vm_only),
        RouteRefusal::NoEligibleEndpoint { ineligible } if ineligible[0].reason
            == Ineligible::CategoryNotAccepted { category: ExecutionCategory::SharedKernelGpuRuntime }
    ));
}

#[test]
fn another_model_is_never_substituted_however_fast() {
    let world = World::new();
    let other = world.synthetic.other.identity().unwrap();
    let mut faster = world.ready("host-c", SecondsEstimate::ZERO, estimate(0.5, 0.0));
    faster.state = EndpointState::Ready(
        world
            .synthetic
            .resident_claim(
                world.fleet_authority(),
                world.gpu("host-c"),
                world.synthetic.scope("host-c"),
                other,
                ModelActivationGeneration::FIRST,
                FAR,
            )
            .unwrap(),
    );
    let exact = world.ready("host-a", estimate(3.0, 0.0), estimate(1.5, 0.0));
    let request = world.request(&["host-a", "host-c"], None);
    let decision = router(0.25, 0.05)
        .route(&request, &[faster.clone(), exact], &world.clock)
        .unwrap();
    assert_eq!(decision.chosen.device, world.gpu("host-a"));
    assert_eq!(
        decision.ineligible[0].reason,
        Ineligible::NotRequestedModel { offered: other }
    );
    // With only the other model available nothing is chosen.
    assert!(matches!(
        router(0.25, 0.05).route(&request, &[faster], &world.clock),
        Err(RouteRefusal::NoEligibleEndpoint { .. })
    ));
    // The same logical model under another rank topology is another execution: refused
    // unless the request lists it.
    let pipeline = world.synthetic.pipeline_execution().unwrap();
    let mut staged = world.ready("host-a", SecondsEstimate::ZERO, estimate(1.0, 0.0));
    staged.state = EndpointState::Ready(
        world
            .synthetic
            .resident_claim(
                world.fleet_authority(),
                world.gpu("host-a"),
                world.synthetic.scope("host-a"),
                pipeline,
                ModelActivationGeneration::FIRST,
                FAR,
            )
            .unwrap(),
    );
    assert!(matches!(
        router(0.25, 0.05).route(&world.request(&["host-a"], None), &[staged.clone()], &world.clock),
        Err(RouteRefusal::NoEligibleEndpoint { ineligible })
            if ineligible[0].reason == Ineligible::NotRequestedModel { offered: pipeline }
    ));
    let mut both = world.request(&["host-a"], None);
    both.model = world.synthetic.requested_single_or_pipeline().unwrap();
    assert!(router(0.25, 0.05)
        .route(&both, &[staged], &world.clock)
        .is_ok());
    // A requested model never mixes logical models.
    assert_eq!(
        RequestedModel::with_executions(
            world.synthetic.logical.identity(),
            &[
                world.synthetic.single.clone(),
                world.synthetic.other.clone()
            ],
        ),
        Err(RoutingError::MixedLogicalModels)
    );
}

#[test]
fn a_cold_endpoint_needs_a_grant_for_its_source() {
    let world = World::new();
    let request = world.request(&["host-b"], None);
    let mut ungranted = world.cold("host-b", estimate(2.8, 0.0), estimate(1.5, 0.0));
    if let EndpointState::Cold { source, .. } = &mut ungranted.state {
        if let PreparationSource::LocalArtifact { grant, .. } = source {
            *grant = None;
        }
    }
    let (_, ineligible) = router(0.25, 0.05)
        .evaluate(&request, &[ungranted], &world.clock)
        .unwrap();
    assert_eq!(
        ineligible[0].reason,
        Ineligible::LocalArtifactGrant(GrantRefusal::Missing)
    );

    // A peer's resident copy moves only under a transfer grant for the recipient scope.
    let peer_claim = |uses: &[GrantedUse], scope| {
        let mut claim = world
            .synthetic
            .resident_claim(
                world.fleet_authority(),
                world.gpu("host-a"),
                world.synthetic.scope("host-a"),
                world.synthetic.single_execution().unwrap(),
                ModelActivationGeneration::FIRST,
                FAR,
            )
            .unwrap();
        claim.grant = Some(
            world
                .synthetic
                .grant(world.fleet_authority(), scope, uses, FAR)
                .unwrap(),
        );
        claim
    };
    let from_peer = |claim| {
        let mut endpoint = world.cold("host-b", estimate(2.8, 0.0), estimate(1.5, 0.0));
        endpoint.egress_usd_per_byte = 1e-10;
        if let EndpointState::Cold { source, .. } = &mut endpoint.state {
            *source = PreparationSource::PeerResident {
                claim,
                bytes: 14_000_000_000,
                interference_seconds_per_byte: 1e-10,
            };
        }
        endpoint
    };
    let serve_only = from_peer(peer_claim(
        &[GrantedUse::Serve],
        world.synthetic.scope("host-a"),
    ));
    let (_, ineligible) = router(0.25, 0.05)
        .evaluate(&request, &[serve_only], &world.clock)
        .unwrap();
    assert_eq!(
        ineligible[0].reason,
        Ineligible::SourceAdvertisement(AdvertisementRefusal::Unauthorized(
            GrantRefusal::ForAnotherScope
        ))
    );
    let transfer = from_peer(peer_claim(
        &[GrantedUse::Transfer],
        world.synthetic.scope("host-b"),
    ));
    let mut valued = policy(0.25, 0.05);
    valued.seconds_per_usd = 2.0;
    let (options, _) = JointRouter::new(valued)
        .unwrap()
        .evaluate(&request, &[transfer.clone()], &world.clock)
        .unwrap();
    let option = &options[0];
    assert!(matches!(
        option.authority,
        RouteAuthority::PreparedFromPeer(_)
    ));
    assert_eq!(option.egress_bytes, 14_000_000_000);
    assert_close(option.egress_usd, 1.4);
    // 1.4 s of donor interference; score 4.32 + 2.8 (egress) + 1.4 (donor).
    assert_close(option.donor_impact_seconds, 1.4);
    assert_close(option.score_seconds, 4.32 + 2.8 + 1.4);
    let mut budgeted = request.clone();
    budgeted.restrictions.max_egress_usd = Some(1.0);
    let (_, ineligible) = router(0.25, 0.05)
        .evaluate(&budgeted, &[transfer], &world.clock)
        .unwrap();
    assert!(matches!(
        ineligible[0].reason,
        Ineligible::EgressBudgetExceeded { budget_usd, .. } if budget_usd == 1.0
    ));
}

#[test]
fn input_data_on_another_machine_needs_a_measured_link() {
    let world = World::new();
    let mut request = world.request(&["host-a"], None);
    request.input = Some(InputData {
        machine: world.gpu("host-x").machine,
        bytes: 2_500_000_000,
    });
    let mut endpoint = world.ready("host-a", SecondsEstimate::ZERO, estimate(1.0, 0.0));
    let (_, ineligible) = router(0.25, 0.05)
        .evaluate(&request, &[endpoint.clone()], &world.clock)
        .unwrap();
    assert_eq!(ineligible[0].reason, Ineligible::NoMeasuredInputLink);
    // An advertised figure is not a measurement either.
    endpoint.input_link = Some(BandwidthRating::advertised(1.25e9).unwrap());
    let (_, ineligible) = router(0.25, 0.05)
        .evaluate(&request, &[endpoint.clone()], &world.clock)
        .unwrap();
    assert_eq!(ineligible[0].reason, Ineligible::NoMeasuredInputLink);
    endpoint.input_link = Some(BandwidthRating::measured_directional(1.25e9).unwrap());
    let (options, _) = router(0.25, 0.05)
        .evaluate(&request, &[endpoint.clone()], &world.clock)
        .unwrap();
    // 2.5 GB at 1.25 GB/s: 2 s before compute.
    assert_close(
        options[0]
            .finish
            .components
            .state_preparation_critical_path
            .expected_seconds(),
        2.0,
    );
    assert_eq!(options[0].egress_bytes, 2_500_000_000);
    // Data already on the endpoint's machine moves nothing.
    request.input = Some(InputData {
        machine: world.gpu("host-a").machine,
        bytes: 2_500_000_000,
    });
    let (options, _) = router(0.25, 0.05)
        .evaluate(&request, &[endpoint], &world.clock)
        .unwrap();
    assert_eq!(options[0].egress_bytes, 0);
}

/// A session of `context_tokens` homed on host-a, host-a busy for 3 s with 4 s of
/// compute, host-b idle with 2 s of compute, a 1.25 GB/s link and both mechanisms.
fn session_world(world: &World, context_tokens: u32) -> (RoutingRequest, [EndpointReport; 2]) {
    let session = world
        .synthetic
        .session(world.gpu("host-a"), context_tokens, 131_072)
        .unwrap();
    let link = BandwidthRating::measured_directional(1.25e9).unwrap();
    let mut remote = world.ready("host-b", SecondsEstimate::ZERO, estimate(2.0, 0.0));
    remote.migration = MigrationSupport {
        token_reconstruction: Some(TokenReconstructionSupport {
            recompute: KvRecompute {
                held_prefix: Some(session.requirement.prefix_identity),
                produces_state: session.requirement.state_identity,
                authorized_epoch: Some(session.requirement.current_epoch),
                queue_seconds: 0.0,
                compute_seconds: f64::from(context_tokens) / 8_000.0,
            },
            token_bytes: u64::from(context_tokens) * 4,
            link,
        }),
        raw_kv_transfer: Some(RawKvTransferSupport {
            destination_scope: session.scope.clone(),
            enforcement: world.fleet_authority().kv_enforcement.clone(),
            link,
            setup_seconds: 0.05,
        }),
    };
    let home = world.ready("host-a", estimate(3.0, 0.0), estimate(4.0, 0.0));
    (
        world.request(&["host-a", "host-b"], Some(session)),
        [home, remote],
    )
}

#[test]
fn a_short_session_leaves_its_busy_home_when_moving_its_kv_is_cheap() {
    let world = World::new();
    let (request, endpoints) = session_world(&world, 4_096);
    let decision = router(0.25, 0.05)
        .route(&request, &endpoints, &world.clock)
        .unwrap();
    assert_eq!(decision.chosen.device, world.gpu("host-b"));
    // 512 MiB of KV at 1.25 GB/s plus 50 ms setup beats 0.512 s of token reconstruction.
    let plan = decision.chosen.migration.unwrap();
    assert_eq!(plan.mechanism(), MigrationMechanism::RawKvTransfer);
    assert_close(plan.completion_seconds(), 0.05 + 536_870_912.0 / 1.25e9);
    assert_close(
        decision.chosen.finish.finish.expected_seconds(),
        0.4794967296 + 2.02,
    );
}

#[test]
fn a_long_context_session_stays_home_when_migrating_its_kv_takes_too_long() {
    let world = World::new();
    let (request, endpoints) = session_world(&world, 131_072);
    let (options, _) = router(0.25, 0.05)
        .evaluate(&request, &endpoints, &world.clock)
        .unwrap();
    assert_eq!(options[0].device, world.gpu("host-a"));
    assert_close(options[0].finish.finish.expected_seconds(), 7.02);
    // 16 GiB of KV takes 13.79 s; reconstruction would take 16.38 s.
    let remote = &options[1];
    let plan = remote.migration.unwrap();
    assert_eq!(plan.mechanism(), MigrationMechanism::RawKvTransfer);
    assert_close(plan.completion_seconds(), 0.05 + 17_179_869_184.0 / 1.25e9);
    assert!(remote.finish.finish.expected_seconds() > 15.0);
}

#[test]
fn token_reconstruction_and_raw_kv_transfer_are_never_interchangeable() {
    let world = World::new();
    let (request, [home, remote]) = session_world(&world, 131_072);
    let busy_home = EndpointReport {
        queue: estimate(60.0, 0.0),
        ..home
    };
    // Only reconstruction supported: it is priced at its own 16.38 s, not at the 13.79 s
    // a raw transfer would take.
    let mut token_only = remote.clone();
    token_only.migration.raw_kv_transfer = None;
    let decision = router(0.25, 0.05)
        .route(
            &request,
            &[busy_home.clone(), token_only.clone()],
            &world.clock,
        )
        .unwrap();
    let plan = decision.chosen.migration.unwrap();
    assert_eq!(plan.mechanism(), MigrationMechanism::TokenReconstruction);
    assert_close(
        plan.completion_seconds(),
        524_288.0 / 1.25e9 + 131_072.0 / 8_000.0,
    );
    assert_eq!(
        plan.check_execution(MigrationMechanism::RawKvTransfer),
        Err(MigrationRefusal::MechanismMismatch {
            planned: MigrationMechanism::TokenReconstruction,
            offered: MigrationMechanism::RawKvTransfer,
        })
    );
    assert_eq!(
        plan.check_execution(MigrationMechanism::TokenReconstruction),
        Ok(())
    );

    // Raw transfer into another KV representation is refused, and with no other
    // mechanism the session cannot move: its context is never dropped.
    let mut raw_mismatch = remote.clone();
    raw_mismatch.migration.token_reconstruction = None;
    if let Some(raw) = &mut raw_mismatch.migration.raw_kv_transfer {
        raw.destination_scope.cache = KvRepresentation::new(
            Dtype::Float8E4M3,
            Quantization::None,
            16,
            VersionedName::new("paged", "1").unwrap(),
        )
        .unwrap();
    }
    let (_, ineligible) = router(0.25, 0.05)
        .evaluate(&request, &[raw_mismatch], &world.clock)
        .unwrap();
    assert_eq!(
        ineligible[0].reason,
        Ineligible::SessionUnreachable {
            token_reconstruction: MechanismUnavailable::NotSupported,
            raw_kv_transfer: MechanismUnavailable::KvScope(KvReuseRefusal::ScopeMismatch {
                components: vec![KvScopeComponent::CacheRepresentation]
            }),
        }
    );

    // Reconstruction follows the §2.8 rule; an unverified backend gets no raw KV.
    let mut stale_epoch = remote;
    if let Some(token) = &mut stale_epoch.migration.token_reconstruction {
        token.recompute.authorized_epoch = None;
    }
    if let Some(raw) = &mut stale_epoch.migration.raw_kv_transfer {
        raw.enforcement = ScopeEnforcement::NotVerified;
    }
    let (_, ineligible) = router(0.25, 0.05)
        .evaluate(&request, &[stale_epoch], &world.clock)
        .unwrap();
    assert_eq!(
        ineligible[0].reason,
        Ineligible::SessionUnreachable {
            token_reconstruction: MechanismUnavailable::Recompute(RecomputeRefusal::NotAuthorized),
            raw_kv_transfer: MechanismUnavailable::KvScope(
                KvReuseRefusal::BackendDoesNotEnforceScope
            ),
        }
    );
}

#[test]
fn hysteresis_keeps_a_flow_from_flip_flopping_on_near_equal_estimates() {
    let world = World::new();
    let request = world.request(&["host-a", "host-b"], None);
    let pair = |a: f64, b: f64| {
        [
            world.ready("host-a", estimate(a, 0.0), SecondsEstimate::ZERO),
            world.ready("host-b", estimate(b, 0.0), SecondsEstimate::ZERO),
        ]
    };
    let flips = |router: &mut JointRouter| {
        let mut previous = None;
        let mut flips = 0;
        for round in 0..20 {
            let (a, b) = if round % 2 == 0 {
                (2.0, 2.1)
            } else {
                (2.1, 2.0)
            };
            let chosen = router
                .route(&request, &pair(a, b), &world.clock)
                .unwrap()
                .chosen
                .device;
            if previous.is_some_and(|device| device != chosen) {
                flips += 1;
            }
            previous = Some(chosen);
        }
        flips
    };
    let mut steady = router(0.25, 0.05);
    assert_eq!(flips(&mut steady), 0);
    assert_eq!(steady.current(&request.flow), Some(&world.gpu("host-a")));
    // Without a threshold the same estimates flip on every request.
    assert_eq!(flips(&mut router(0.0, 0.0)), 19);
    // A clear gain moves the flow: 2.02 against 3.02 clears max(0.25, 5%).
    let decision = steady
        .route(&request, &pair(3.0, 2.0), &world.clock)
        .unwrap();
    assert_eq!(decision.chosen.device, world.gpu("host-b"));
    assert!(!decision.kept_by_hysteresis);
    // A gain inside the band is reported as kept.
    let decision = steady
        .route(&request, &pair(1.9, 2.0), &world.clock)
        .unwrap();
    assert!(decision.kept_by_hysteresis);
    assert_eq!(decision.best, world.gpu("host-a"));
    assert_eq!(decision.chosen.device, world.gpu("host-b"));
    // The held endpoint no longer eligible: the flow moves regardless.
    let mut gone = pair(1.9, 2.0);
    gone[1].observed_at = seconds_ago(6.0);
    let decision = steady.route(&request, &gone, &world.clock).unwrap();
    assert_eq!(decision.chosen.device, world.gpu("host-a"));
}

#[test]
fn the_stale_report_counterexample_breaks_the_assumption() {
    // §4.6 claim record: a report 1 s old from an idle endpoint hides a burst of ten
    // 1.5 s requests admitted since. The router picks it, though its true finish is
    // later than the ready endpoint's.
    let world = World::new();
    let mut hidden_burst = world.ready("host-b", SecondsEstimate::ZERO, estimate(1.5, 0.0));
    hidden_burst.observed_at = seconds_ago(1.0);
    let honest = world.ready("host-a", estimate(3.0, 0.3), estimate(1.5, 0.0));
    let decision = router(0.25, 0.05)
        .route(
            &world.request(&["host-a", "host-b"], None),
            &[honest, hidden_burst],
            &world.clock,
        )
        .unwrap();
    assert_eq!(decision.chosen.device, world.gpu("host-b"));
    let true_finish_b = 10.0 * 1.5 + 1.5 + 0.02;
    let true_finish_a = 3.0 + 1.5 + 0.02;
    assert!(true_finish_b > true_finish_a);
}

#[test]
fn duplicate_endpoints_and_invalid_policies_are_refused() {
    let world = World::new();
    let endpoint = world.ready("host-a", SecondsEstimate::ZERO, SecondsEstimate::ZERO);
    assert!(matches!(
        router(0.25, 0.05).evaluate(
            &world.request(&["host-a"], None),
            &[endpoint.clone(), endpoint],
            &world.clock
        ),
        Err(RoutingError::Input(_))
    ));
    let mut negative = policy(0.25, 0.05);
    negative.risk_weight = -1.0;
    assert!(JointRouter::new(negative).is_err());
    assert_eq!(MonotonicTime::ZERO.as_nanos(), 0);
}
