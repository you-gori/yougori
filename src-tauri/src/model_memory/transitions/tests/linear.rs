//! Line 862, linear workflows: the bounded dynamic program over valid retained-state
//! configurations, with transition peaks.

use super::support::*;
use crate::model_memory::residency::eviction::EvictionAction;
use crate::model_memory::transitions::model::{Context, CostModel, Knowledge};
use crate::model_memory::transitions::*;

fn compile_ok(declaration: &WorkflowDeclaration) -> ReadinessPlan {
    compile(
        declaration,
        &FakeHolds::honoured(),
        &FakeHolds::honoured(),
        &clock(),
    )
    .unwrap()
}

#[test]
fn the_dynamic_program_finds_the_hand_worked_optimum_of_a_b_a() {
    // A is 9 GB and B 7 GB on a 24 GB budget with a 1 GB reserve; links move 2 GB/s.
    // s1: load A, 4.5 s, then prefill 0.5 s and the first token 0.01 s: 5.01 s.
    // During s1 (5 s) B is prepared in 3.5 s, so s2 waits only for its own work: 0.51 s.
    // B's 6.5 GB KV pool leaves no room for A during s2 (9 + 7 + 7.5 + 1 = 24.5 GB), so s3
    // reloads A: 5.01 s. The optimum is 5.01 + 0.51 + 5.01 = 10.53 s.
    let plan = compile_ok(&aba());
    assert_eq!(plan.method(), SearchMethod::ExactDp);
    assert!(
        close(plan.expected_cost_seconds(), 10.53),
        "{}",
        plan.expected_cost_seconds()
    );
    let nodes = plan.nodes();
    assert_eq!(nodes.len(), 3);
    assert_eq!(nodes[0].config, vec![key("model-a")]);
    assert_eq!(nodes[0].prefetch, vec![key("model-b")]);
    assert!(close(nodes[0].readiness.expected_seconds, 5.01));
    assert_eq!(nodes[1].config, vec![key("model-b")]);
    assert!(nodes[1].prefetch.is_empty());
    assert!(close(nodes[1].readiness.expected_seconds, 0.51));
    assert_eq!(nodes[2].config, vec![key("model-a")]);
    assert!(close(nodes[2].readiness.expected_seconds, 5.01));
    // The s1→s2 peak is s1 running with B prepared beside it: A 9 + B 7 + KV 2 + two
    // contexts 1 + workspace 0.5 + staging 0.5 + reserve 1 = 21 GB.
    let peak = &nodes[1].peak;
    assert_eq!(peak.peak_bytes, 21 * GB);
    assert_eq!(peak.during, TransitionSlot::PreviousStage);
    assert_eq!(peak.breakdown.unique_resident_weights_bytes, 16 * GB);
    assert_eq!(peak.breakdown.contexts_bytes, GB);
    assert_eq!(peak.breakdown.staging_bytes, GB / 2);
    assert!(peak
        .assumptions
        .contains(&Assumption::PreparationEngineContext { bytes: GB / 2 }));
    assert!(peak
        .assumptions
        .contains(&Assumption::UsableVramFromLedger { bytes: 24 * GB }));
    // Readiness is an estimate with its interval (line 864).
    assert!(nodes[0].readiness.low_seconds < 5.01 && nodes[0].readiness.high_seconds > 5.01);

    // Without room to prepare, s2 loads B itself: 3.5 + 0.51 = 4.01 s, 14.03 s in all.
    let mut tight = aba();
    tight.budgets.max_preparation_bytes = 6 * GB;
    let unprepared = compile_ok(&tight);
    assert!(close(unprepared.expected_cost_seconds(), 14.03));
    assert!(unprepared.nodes()[0].prefetch.is_empty());
}

#[test]
fn the_oracle_agrees_with_the_dynamic_program_on_the_linear_case() {
    let holds = FakeHolds::honoured();
    let exact = compile_with(&aba(), &holds, &holds, &clock(), SearchMethod::ExactDp).unwrap();
    let oracle = compile_with(
        &aba(),
        &holds,
        &holds,
        &clock(),
        SearchMethod::ExhaustiveOracle,
    )
    .unwrap();
    assert!(close(
        exact.expected_cost_seconds(),
        oracle.expected_cost_seconds()
    ));
}

#[test]
fn a_plan_never_swaps_through_a_second_full_copy_that_does_not_fit() {
    let workflow = CheckedWorkflow::check(&aba()).unwrap();
    let clock = clock();
    let mut model = CostModel::new(&workflow, workflow.tree(), &clock);
    let a = workflow.resource_index(&key("model-a")).unwrap();
    let b = workflow.resource_index(&key("model-b")).unwrap();
    // Preparing A during s2 beside B: 7 + 9 + KV 6.5 + two contexts 1 + workspace 0.5 +
    // staging 0.5 + reserve 1 = 25.5 GB of 24.
    let refusal = model
        .preparation_fits(1, ResourceSet::single(b), ResourceSet::single(a))
        .unwrap()
        .unwrap_err();
    assert_eq!(
        refusal,
        Infeasibility::TransitionPeak {
            during: TransitionSlot::PreviousStage,
            peak_bytes: 25_500 * MB,
            usable_vram_bytes: 24 * GB,
            largest_term: "unique resident weights".into(),
            largest_term_bytes: 16 * GB,
        }
    );
    // Keeping A beside B through s2: 9 + 7 + 7.5 + 1 = 24.5 GB while s2 runs.
    let context = model
        .context_after(
            0,
            ResourceSet::single(a),
            ResourceSet::single(b),
            ResourceSet::EMPTY,
        )
        .unwrap();
    let refusal = model
        .transition(
            &context,
            1,
            ResourceSet::single(a).with(b),
            Knowledge::Declared,
        )
        .unwrap()
        .unwrap_err();
    assert!(matches!(
        refusal,
        Infeasibility::TransitionPeak {
            during: TransitionSlot::NextStage,
            peak_bytes,
            ..
        } if peak_bytes == 24_500 * MB
    ));
    // The compiled plan does neither.
    let plan = compile_ok(&aba());
    assert!(plan.nodes()[1].prefetch.is_empty());
    assert_eq!(plan.nodes()[1].config, vec![key("model-b")]);
}

fn merged_workflow(usable_gb: u64, with_reload: bool) -> WorkflowDeclaration {
    let derive = RecoveryRecipe::Derive {
        sources: vec![key("model-a"), key("adapter-x")],
        compute_seconds: 1.0,
    };
    let mut recipes = vec![derive];
    if with_reload {
        recipes.push(reload("merged-ax"));
    }
    let mut declared = declaration(
        vec![
            base("model-a", 9 * GB),
            adapter("adapter-x", "model-a", GB),
            merged("merged-ax", 9 * GB, recipes),
        ],
        vec![
            stage("s1", &["model-a", "adapter-x"]),
            stage("s2", &["merged-ax"]),
        ],
        chain(&["s1", "s2"]),
    );
    declared.budgets.usable_vram = crate::model_memory::residency::Capacity::Physical {
        bytes: usable_gb * GB,
    };
    declared
}

#[test]
fn deriving_a_merged_variant_counts_its_sources_and_the_copy_together() {
    // Building the merged variant keeps base 9 + adapter 1 + variant 9 + s2's context and
    // pool 2.5 + workspace 0.5 + reserve 1 = 23 GB at the boundary. On 22 GB that second
    // full copy does not fit, and with no other recipe no plan exists.
    match compile(
        &merged_workflow(22, false),
        &FakeHolds::honoured(),
        &FakeHolds::honoured(),
        &clock(),
    ) {
        Err(TransitionError::NoFeasiblePlan { infeasibility, .. }) => assert_eq!(
            infeasibility,
            Infeasibility::TransitionPeak {
                during: TransitionSlot::Boundary,
                peak_bytes: 23 * GB,
                usable_vram_bytes: 22 * GB,
                largest_term: "unique resident weights".into(),
                largest_term_bytes: 18 * GB,
            }
        ),
        other => panic!("expected no feasible plan, got {other:?}"),
    }
    // With a catalog copy of the variant, the plan evicts base and adapter and loads it.
    let loaded = compile_ok(&merged_workflow(22, true));
    let actions = &loaded.nodes()[1].actions;
    assert!(actions.iter().any(|action| matches!(
        action,
        PlanAction::Materialize { resource, via: Materialization::Load { .. } }
            if resource == &key("merged-ax")
    )));
    assert!(actions.iter().any(|action| matches!(
        action,
        PlanAction::Evict { resource, handling: EvictionHandling::Residency(EvictionAction::DropClean { .. }) }
            if resource == &key("model-a")
    )));
    assert!(close(loaded.nodes()[1].readiness.expected_seconds, 5.01));
    // With room for both and no room to prepare the variant during s1, deriving (1 s on
    // the GPU) beats loading (4.5 s): 1.51 s.
    let mut roomy = merged_workflow(24, true);
    roomy.budgets.max_preparation_bytes = 4 * GB;
    let derived = compile_ok(&roomy);
    let node = &derived.nodes()[1];
    assert!(close(node.readiness.expected_seconds, 1.51));
    assert_eq!(node.peak.peak_bytes, 23 * GB);
    assert!(node
        .peak
        .assumptions
        .contains(&Assumption::DeriveSourcesHeldUntilBuilt));
}

#[test]
fn a_shared_base_counts_once_for_its_adapters() {
    let declared = declaration(
        vec![
            base("model-m", 10 * GB),
            adapter("adapter-x", "model-m", GB / 2),
            adapter("adapter-y", "model-m", GB / 2),
        ],
        vec![
            stage("s1", &["adapter-x"]),
            stage("s2", &["adapter-y"]),
            stage("s3", &["adapter-x"]),
        ],
        chain(&["s1", "s2", "s3"]),
    );
    let plan = compile_ok(&declared);
    // The base stays; only adapters move. With both adapters resident the device holds the
    // base once: 10 GB of weights and 1 GB of adapters.
    for node in plan.nodes() {
        assert!(node.config.contains(&key("model-m")));
        assert!(node.peak.breakdown.unique_resident_weights_bytes <= 10 * GB);
    }
    let last = &plan.nodes()[2];
    assert_eq!(last.peak.breakdown.adapters_bytes, GB);
    assert!(close(last.readiness.expected_seconds, 0.51));
}

fn long_context(usable_gb: u64, write_back: bool, host_copy_bytes: u64) -> WorkflowDeclaration {
    let mut first = stage("s1", &["model-a"]);
    first.produces = Some(key("session-long"));
    first.process.kv_pool_bytes = 8 * GB;
    let mut last = stage("s3", &["model-a", "session-long"]);
    last.process.kv_pool_bytes = 8 * GB;
    let mut declared = declaration(
        vec![
            base("model-a", 9 * GB),
            base("model-b", 7 * GB),
            session("session-long", "model-a", &[7, 8, 9], 8 * GB, Vec::new()),
        ],
        vec![first, stage("s2", &["model-b"]), last],
        chain(&["s1", "s2", "s3"]),
    );
    declared.budgets.write_back =
        write_back.then_some(crate::model_memory::residency::eviction::CopyTier::PinnedHost);
    declared.budgets.host_copy_bytes = host_copy_bytes;
    declared.budgets.usable_vram = crate::model_memory::residency::Capacity::Physical {
        bytes: usable_gb * GB,
    };
    declared
}

#[test]
fn live_session_state_is_kept_or_written_back_never_dropped() {
    // A live session can leave the device only by write-back (line 307), and it stays
    // only with its base. Without a write-back tier, 32 GB keeps both through s2:
    // A 9 + session 8 with its holder's 0.5 GB context + B 7 + s2 3 + reserve 1 = 28.5 GB.
    let kept = compile_ok(&long_context(32, false, 64 * GB));
    assert!(kept.nodes()[1].config.contains(&key("session-long")));
    assert!(kept.nodes()[1].config.contains(&key("model-a")));
    assert!(kept.nodes()[1]
        .peak
        .assumptions
        .contains(&Assumption::SessionHolderContext {
            resource: "session-long".into(),
            bytes: GB / 2
        }));
    // On 24 GB that does not fit, and the session cannot leave: no plan exists.
    match compile(
        &long_context(24, false, 64 * GB),
        &FakeHolds::honoured(),
        &FakeHolds::honoured(),
        &clock(),
    ) {
        Err(TransitionError::NoFeasiblePlan { infeasibility, .. }) => assert_eq!(
            infeasibility,
            Infeasibility::MustRetain {
                resource: "session-long".into()
            }
        ),
        other => panic!("expected no feasible plan, got {other:?}"),
    }
    // Forcing it out without a write-back tier is refused.
    let workflow = CheckedWorkflow::check(&long_context(24, false, 64 * GB)).unwrap();
    let clock = clock();
    let mut model = CostModel::new(&workflow, workflow.tree(), &clock);
    let a = workflow.resource_index(&key("model-a")).unwrap();
    let b = workflow.resource_index(&key("model-b")).unwrap();
    let context = model
        .context_after(
            0,
            ResourceSet::single(a),
            ResourceSet::EMPTY,
            ResourceSet::EMPTY,
        )
        .unwrap();
    let refusal = model
        .transition(&context, 1, ResourceSet::single(b), Knowledge::Declared)
        .unwrap()
        .unwrap_err();
    assert_eq!(
        refusal,
        Infeasibility::MustRetain {
            resource: "session-long".into()
        }
    );
    // With a write-back tier but too small a host budget the copy is refused too.
    let workflow = CheckedWorkflow::check(&long_context(24, true, 4 * GB)).unwrap();
    let mut model = CostModel::new(&workflow, workflow.tree(), &clock);
    let refusal = model
        .transition(&context, 1, ResourceSet::single(b), Knowledge::Declared)
        .unwrap()
        .unwrap_err();
    assert_eq!(
        refusal,
        Infeasibility::HostCopyBudget {
            needed_bytes: 8 * GB,
            budget_bytes: 4 * GB
        }
    );
    // With room for the copy, evicting writes it back: 8 GB at 2 GB/s before s2.
    let workflow = CheckedWorkflow::check(&long_context(24, true, 64 * GB)).unwrap();
    let mut model = CostModel::new(&workflow, workflow.tree(), &clock);
    let written = model
        .transition(&context, 1, ResourceSet::single(b), Knowledge::Declared)
        .unwrap()
        .unwrap();
    assert!(close(written.write_back_seconds, 4.0));
    assert!(written.evictions.iter().any(|(_, handling)| matches!(
        handling,
        EvictionHandling::Residency(EvictionAction::WriteBackThenDrop { .. })
    )));
}

#[test]
fn dead_session_state_is_dropped_without_a_copy() {
    // §3.9: drop dead session KV while retaining the base. s1 produces a session no later
    // stage consumes; s2 then has room to keep A beside B. Preparation is charged, so
    // keeping A beats evicting it and preparing it again during s2.
    let mut first = stage("s1", &["model-a"]);
    first.produces = Some(key("session-dead"));
    first.process.kv_pool_bytes = 6 * GB;
    let declared = declaration(
        vec![
            base("model-a", 9 * GB),
            base("model-b", 7 * GB),
            session("session-dead", "model-a", &[1], 6 * GB, Vec::new()),
        ],
        vec![first, stage("s2", &["model-b"]), stage("s3", &["model-a"])],
        chain(&["s1", "s2", "s3"]),
    );
    let mut declared = declared;
    declared.weights.preparation_seconds_per_byte = 1e-11;
    let plan = compile_ok(&declared);
    let s2 = &plan.nodes()[1];
    assert!(s2.actions.iter().any(|action| matches!(
        action,
        PlanAction::Evict { resource, handling: EvictionHandling::DropDeadSession }
            if resource == &key("session-dead")
    )));
    assert!(s2.config.contains(&key("model-a")));
    assert!(close(plan.nodes()[2].readiness.expected_seconds, 0.51));
}

#[test]
fn deadlines_are_hard_constraints_on_predicted_readiness() {
    let mut declared = aba();
    declared.stages[2].readiness_deadline_seconds = Some(1.0);
    match compile(
        &declared,
        &FakeHolds::honoured(),
        &FakeHolds::honoured(),
        &clock(),
    ) {
        Err(TransitionError::NoFeasiblePlan {
            infeasibility:
                Infeasibility::DeadlineMissed {
                    stage,
                    deadline_seconds,
                    ..
                },
            ..
        }) => {
            assert_eq!(stage, "s3");
            assert!(close(deadline_seconds, 1.0));
        }
        other => panic!("expected a missed deadline, got {other:?}"),
    }
    declared.stages[2].readiness_deadline_seconds = Some(6.0);
    assert!(compile(
        &declared,
        &FakeHolds::honoured(),
        &FakeHolds::honoured(),
        &clock()
    )
    .is_ok());
}

#[test]
fn preparation_beyond_the_maximum_cost_is_refused() {
    let mut declared = aba();
    declared.budgets.max_preparation_bytes = 6 * GB;
    let workflow = CheckedWorkflow::check(&declared).unwrap();
    let clock = clock();
    let mut model = CostModel::new(&workflow, workflow.tree(), &clock);
    let a = workflow.resource_index(&key("model-a")).unwrap();
    let b = workflow.resource_index(&key("model-b")).unwrap();
    assert_eq!(
        model
            .preparation_fits(0, ResourceSet::single(a), ResourceSet::single(b))
            .unwrap(),
        Err(Infeasibility::PreparationBudget {
            bytes: 7 * GB,
            budget_bytes: 6 * GB
        })
    );
}

#[test]
fn retained_memory_is_charged() {
    // A and B are 6 GB each, so A fits beside B through s2 and saves s3's 3 s reload.
    // Nothing may be prepared, so keeping A is the only way to have it ready.
    let mut declared = declaration(
        vec![base("model-a", 6 * GB), base("model-b", 6 * GB)],
        vec![
            stage("s1", &["model-a"]),
            stage("s2", &["model-b"]),
            stage("s3", &["model-a"]),
        ],
        chain(&["s1", "s2", "s3"]),
    );
    declared.budgets.max_preparation_bytes = 0;
    let free = compile_ok(&declared);
    assert_eq!(free.nodes()[1].config, vec![key("model-a"), key("model-b")]);
    // s1: 3 + 0.51; s2: 3 + 0.51; s3: A kept, 0.51.
    assert!(close(free.expected_cost_seconds(), 7.53));
    // Charging 1e-9 s per retained byte-second makes keeping A through s2 cost
    // 6 GB × 5 s × 1e-9 = 30 s, more than the 3 s reload it saves.
    let mut charged = declared.clone();
    charged.weights.retained_seconds_per_byte_second = 1e-9;
    let plan = compile_ok(&charged);
    assert_eq!(plan.nodes()[1].config, vec![key("model-b")]);
    assert!(close(plan.nodes()[2].readiness.expected_seconds, 3.51));
    assert!(close(plan.expected_cost_seconds(), 10.53));
}

#[test]
fn initially_resident_state_is_ready() {
    let mut declared = aba();
    declared.initial = vec![key("model-a")];
    let plan = compile_ok(&declared);
    assert!(close(plan.nodes()[0].readiness.expected_seconds, 0.51));
}

#[test]
fn the_search_respects_its_work_bound() {
    let mut declared = aba();
    declared.limits.max_work_units = 3;
    assert_eq!(
        compile(
            &declared,
            &FakeHolds::honoured(),
            &FakeHolds::honoured(),
            &clock()
        )
        .unwrap_err(),
        TransitionError::WorkBoundExceeded { limit: 3 }
    );
}

#[test]
fn planning_time_is_work_units_times_their_measured_cost() {
    let plan = compile_ok(&aba());
    assert!(plan.work_units() > 0);
    assert!(close(
        plan.planning_seconds(),
        plan.work_units() as f64 * 1e-6
    ));
}

#[test]
fn the_boundary_view_checks_only_what_is_still_ahead() {
    // At runtime the previous stage is history: its preparation is not checked again.
    let workflow = CheckedWorkflow::check(&aba()).unwrap();
    let clock = clock();
    let a = workflow.resource_index(&key("model-a")).unwrap();
    let b = workflow.resource_index(&key("model-b")).unwrap();
    let mut model = CostModel::new(&workflow, workflow.tree(), &clock).with_usable_vram(17 * GB);
    let context: Context = model
        .context_after(
            0,
            ResourceSet::single(a),
            ResourceSet::single(b),
            ResourceSet::EMPTY,
        )
        .unwrap();
    // Seen from before s1 ended, the 21 GB of s1 with B prepared does not fit 17 GB.
    assert!(model
        .transition(&context, 1, ResourceSet::single(b), Knowledge::Declared)
        .unwrap()
        .is_err());
    // From the boundary, s2 alone needs 15.5 GB.
    let ahead = model
        .transition(
            &context.at_boundary(),
            1,
            ResourceSet::single(b),
            Knowledge::Declared,
        )
        .unwrap()
        .unwrap();
    assert_eq!(ahead.peak.peak_bytes, 15_500 * MB);
}
