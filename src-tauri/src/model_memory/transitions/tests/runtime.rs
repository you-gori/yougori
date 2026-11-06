//! Line 864: runtime validation of identities, capacity and branch decisions; deviations
//! invalidate the affected suffix and invoke bounded replanning; correctness constraints
//! stay hard and readiness times are estimates.

use super::support::*;
use crate::foundation::ids::ManualClock;
use crate::model_memory::residency::eviction::EvictionAction;
use crate::model_memory::residency::Capacity;
use crate::model_memory::transitions::*;

/// A→B→A where A fits beside B: the plan keeps A through s2, since preparing it again
/// would be charged. A third base C is declared but used by no stage.
fn roomy() -> WorkflowDeclaration {
    let mut declared = declaration(
        vec![
            base("model-a", 9 * GB),
            base("model-b", 7 * GB),
            base("model-c", 7 * GB),
        ],
        vec![
            stage("s1", &["model-a"]),
            stage("s2", &["model-b"]),
            stage("s3", &["model-a"]),
        ],
        chain(&["s1", "s2", "s3"]),
    );
    declared.weights.preparation_seconds_per_byte = 1e-11;
    declared
}

struct World {
    holds: FakeHolds,
    clock: ManualClock,
    runtime: PlanRuntime,
}

impl World {
    fn new(declared: &WorkflowDeclaration) -> Self {
        let holds = FakeHolds::honoured();
        let clock = clock();
        let plan = compile(declared, &holds, &holds, &clock).unwrap();
        Self {
            runtime: PlanRuntime::new(plan),
            holds,
            clock,
        }
    }

    fn identity(&self, model: &str) -> StateIdentity {
        let workflow = self.runtime.plan().workflow();
        workflow.resources()[workflow.resource_index(&key(model)).unwrap()]
            .identity()
            .clone()
    }

    fn advance_with(
        &mut self,
        stage: &str,
        presented: Vec<StateIdentity>,
        usable_gb: u64,
        previous_seconds: Option<f64>,
    ) -> BoundaryOutcome {
        let observation = BoundaryObservation {
            next_stage: stage_id(stage),
            presented,
            usable_vram: Capacity::Physical {
                bytes: usable_gb * GB,
            },
            previous_stage_seconds: previous_seconds,
            holds: &self.holds,
            objects: &self.holds,
        };
        self.runtime.advance(&observation, &self.clock).unwrap()
    }

    fn advance(&mut self, stage: &str, model: &str) -> BoundaryOutcome {
        let presented = vec![self.identity(model)];
        self.advance_with(stage, presented, 24, Some(5.0))
    }
}

fn planned(outcome: BoundaryOutcome) -> Directive {
    match outcome {
        BoundaryOutcome::Planned(directive) => directive,
        other => panic!("expected the plan to hold, got {other:?}"),
    }
}

fn replanned(outcome: BoundaryOutcome) -> (Vec<Deviation>, Vec<(usize, StageId)>, Directive) {
    match outcome {
        BoundaryOutcome::Replanned {
            deviations,
            invalidated,
            directive,
            ..
        } => (deviations, invalidated, directive),
        other => panic!("expected a replan, got {other:?}"),
    }
}

#[test]
fn without_deviations_the_runtime_follows_the_plan() {
    let mut world = World::new(&roomy());
    let first = planned(world.advance("s1", "model-a"));
    assert_eq!(first.config, vec![key("model-a")]);
    assert_eq!(first.prefetch, vec![key("model-b")]);
    let second = planned(world.advance("s2", "model-b"));
    assert_eq!(second.config, vec![key("model-a"), key("model-b")]);
    let third = planned(world.advance("s3", "model-a"));
    assert!(close(third.readiness.expected_seconds, 0.51));
    assert_eq!(world.runtime.replans(), 0);
    // Correctness stays hard: every directive passed the admission check.
    for directive in [&first, &second, &third] {
        assert!(directive.peak.peak_bytes <= 24 * GB);
    }
}

#[test]
fn an_unexpected_declared_identity_invalidates_the_suffix_and_replans() {
    let mut world = World::new(&roomy());
    planned(world.advance("s1", "model-a"));
    // s2 arrives with model C instead of B: unexpected input.
    let presented = vec![world.identity("model-c")];
    let (deviations, invalidated, directive) =
        replanned(world.advance_with("s2", presented, 24, Some(5.0)));
    assert!(matches!(
        deviations.as_slice(),
        [Deviation::UnexpectedIdentity { stage, .. }] if stage.as_str() == "s2"
    ));
    // The suffix from s2 on is invalidated; s1, already run, is not.
    assert_eq!(invalidated, vec![(1, stage_id("s2")), (2, stage_id("s3"))]);
    assert!(directive.config.contains(&key("model-c")));
    assert!(directive.actions.iter().any(|action| matches!(
        action,
        PlanAction::Materialize { resource, .. } if resource == &key("model-c")
    )));
    assert_eq!(world.runtime.replans(), 1);
    // The replanned suffix then holds.
    planned(world.advance("s3", "model-a"));
}

#[test]
fn an_unknown_identity_falls_back_to_the_online_policy() {
    let mut world = World::new(&roomy());
    planned(world.advance("s1", "model-a"));
    let stranger = StateIdentity::Base {
        execution: execution_of("model-z"),
        artifact: artifact_of("model-z"),
    };
    match world.advance_with("s2", vec![stranger], 24, Some(5.0)) {
        BoundaryOutcome::Online {
            reason: FallbackReason::UnknownIdentity { stage },
            directive: None,
            ..
        } => assert_eq!(stage.as_str(), "s2"),
        other => panic!("expected the online fallback, got {other:?}"),
    }
    // From then on the ordinary online policy serves declared stages.
    match world.advance("s3", "model-a") {
        BoundaryOutcome::Online {
            directive: Some(directive),
            ..
        } => assert!(directive.config.contains(&key("model-a"))),
        other => panic!("expected an online directive, got {other:?}"),
    }
    assert!(world.runtime.is_online());
}

#[test]
fn an_undeclared_branch_invalidates_the_suffix_and_replans() {
    let mut world = World::new(&roomy());
    planned(world.advance("s1", "model-a"));
    // The workflow skips s2 and goes straight to s3, a declared stage on another path.
    let (deviations, invalidated, directive) = replanned(world.advance("s3", "model-a"));
    assert!(matches!(
        deviations.as_slice(),
        [Deviation::UndeclaredBranch { after: Some(after), stage }]
            if after.as_str() == "s1" && stage.as_str() == "s3"
    ));
    assert_eq!(invalidated.len(), 2);
    // A is still resident from s1, so s3 is ready at once.
    assert!(close(directive.readiness.expected_seconds, 0.51));
}

#[test]
fn an_unknown_stage_falls_back_to_the_online_policy() {
    let mut world = World::new(&roomy());
    planned(world.advance("s1", "model-a"));
    match world.advance("s9", "model-a") {
        BoundaryOutcome::Online {
            reason: FallbackReason::UnknownStage { stage },
            ..
        } => assert_eq!(stage.as_str(), "s9"),
        other => panic!("expected the online fallback, got {other:?}"),
    }
}

#[test]
fn external_memory_pressure_invalidates_the_suffix_and_replans() {
    let mut world = World::new(&roomy());
    planned(world.advance("s1", "model-a"));
    // The ledger now grants 18 GB: keeping A beside B needs A 9 + B 7 + s2's context,
    // pool and workspace 3 + reserve 1 = 20 GB while s2 runs.
    let presented = vec![world.identity("model-b")];
    let (deviations, _, directive) = replanned(world.advance_with("s2", presented, 18, Some(5.0)));
    assert_eq!(
        deviations,
        vec![Deviation::ExternalMemoryPressure {
            planned_peak_bytes: 20 * GB,
            usable_vram_bytes: 18 * GB
        }]
    );
    assert_eq!(directive.config, vec![key("model-b")]);
    assert!(directive.peak.peak_bytes <= 18 * GB);
    // s3 must reload A now: 4.5 s plus its own 0.51 s, an estimate.
    let presented = vec![world.identity("model-a")];
    let third = planned(world.advance_with("s3", presented, 18, Some(5.0)));
    assert!(close(third.readiness.expected_seconds, 5.01));
    assert!(third.readiness.high_seconds > third.readiness.expected_seconds);
}

#[test]
fn timing_drift_invalidates_the_suffix_and_replans_with_corrected_estimates() {
    let mut world = World::new(&roomy());
    planned(world.advance("s1", "model-a"));
    // s1 took 10 s instead of the 5 s estimate: every later duration doubles.
    let presented = vec![world.identity("model-b")];
    let (deviations, _, directive) = replanned(world.advance_with("s2", presented, 24, Some(10.0)));
    assert!(matches!(
        deviations.as_slice(),
        [Deviation::TimingDrift { expected_seconds, observed_seconds, .. }]
            if close(*expected_seconds, 5.0) && close(*observed_seconds, 10.0)
    ));
    assert!(close(directive.readiness.expected_seconds, 1.02));
    // Within the 25 % tolerance nothing drifts.
    let mut calm = World::new(&roomy());
    planned(calm.advance("s1", "model-a"));
    let presented = vec![calm.identity("model-b")];
    planned(calm.advance_with("s2", presented, 24, Some(6.0)));
}

#[test]
fn a_lost_hold_invalidates_the_suffix_and_replans_without_its_recipes() {
    // In the tight A→B→A, A must leave during s2. Once the catalog leases on A and B are
    // released, nothing can reload A from the catalog, so the replanned suffix writes A
    // back to pinned host RAM and restores it for s3 (line 307).
    let mut world = World::new(&aba());
    planned(world.advance("s1", "model-a"));
    objects().release_all();
    let (deviations, _, directive) = replanned(world.advance("s2", "model-b"));
    assert!(deviations.iter().all(|deviation| matches!(
        deviation,
        Deviation::HoldLost {
            refusal: RecipeRefusal::ObjectHoldNotHonoured { .. },
            ..
        }
    )));
    assert_eq!(deviations.len(), 2);
    assert!(directive.actions.iter().any(|action| matches!(
        action,
        PlanAction::Evict {
            resource,
            handling: EvictionHandling::Residency(EvictionAction::WriteBackThenDrop { .. })
        } if resource == &key("model-a")
    )));
    let third = planned(world.advance("s3", "model-a"));
    assert!(third.actions.iter().any(|action| matches!(
        action,
        PlanAction::Materialize {
            via: Materialization::RestoreCopy { .. },
            ..
        }
    )));
}

#[test]
fn replanning_is_bounded() {
    let mut declared = roomy();
    declared.limits.max_replans = 1;
    let mut world = World::new(&declared);
    planned(world.advance("s1", "model-a"));
    let presented = vec![world.identity("model-b")];
    replanned(world.advance_with("s2", presented, 24, Some(10.0)));
    let presented = vec![world.identity("model-a")];
    match world.advance_with("s3", presented, 24, Some(40.0)) {
        BoundaryOutcome::Online {
            reason: FallbackReason::ReplanLimit { replans: 1 },
            deviations,
            ..
        } => assert!(matches!(
            deviations.as_slice(),
            [Deviation::TimingDrift { .. }]
        )),
        other => panic!("expected the replan limit, got {other:?}"),
    }
}

#[test]
fn infeasible_replanning_falls_back_to_the_online_policy() {
    let mut world = World::new(&roomy());
    planned(world.advance("s1", "model-a"));
    // 12 GB cannot hold B's stage at all: 7 + 3 + 1 + staging.
    let presented = vec![world.identity("model-b")];
    match world.advance_with("s2", presented, 10, Some(5.0)) {
        BoundaryOutcome::Online {
            reason: FallbackReason::NoFeasiblePlan { .. },
            ..
        } => {}
        other => panic!("expected the online fallback, got {other:?}"),
    }
}
