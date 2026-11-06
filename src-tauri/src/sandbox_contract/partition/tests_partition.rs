//! VM-N1 tests: every rule of VM part §9.1 (lines 2303–2338), §12.3 model 6 and the
//! VM-D12 budgets, each tried against a refusal where the plan says never or must.

use std::collections::BTreeSet;

use super::fakes::*;
use super::plan::{analyze, partition_violations};
use super::*;
use crate::foundation::ids::ContentKey;
use crate::foundation::report::ReportError;
use crate::foundation::transfer::VM_D12_GENERAL_RELEASE_BUDGET_BYTES;

fn valid(spec: WorkflowSpec) -> Workflow {
    Workflow::new(spec).unwrap()
}

fn compartment_index(plan: &CompiledPlan, id: &str) -> u32 {
    plan.compartment_of(&step(id)).unwrap().index
}

#[test]
fn the_five_step_example_compiles_to_fetch_build_and_a_narrow_executor() {
    let workflow = valid(five_step());
    let plan = compile(&workflow, &policy()).unwrap();
    assert_eq!(plan.compartments().len(), 3);
    // 1. The fetch VM gets approved public dependencies and cannot read the project.
    let fetch = plan.compartment_of(&step("fetch")).unwrap();
    assert_eq!(fetch.authorities, ops(&[Authority::RegistryFetch]));
    assert!(fetch.history.is_public());
    // 2. The analysis/build VM reads the project and the dependencies, with no internet.
    let build = plan.compartment_of(&step("build")).unwrap();
    assert_eq!(
        build.authorities,
        ops(&[read("private-repo"), Authority::RunUntrustedCode])
    );
    assert!(!build
        .authorities
        .iter()
        .any(|authority| authority.is_unrestricted_release()));
    assert!(!build.authorities.contains(&credential("repo-token")));
    // 3. The patch is an untrusted, immutable artifact that stays labelled private.
    let patch = &plan.labels()[&data("patch")];
    assert_eq!(patch.secrecy(), &BTreeSet::from([tag("private-repo")]));
    assert_eq!(patch.integrity(), Integrity::Untrusted);
    assert!(workflow.steps()[1].outputs[0].immutable);
    // 4. One exact release operation to one repository and branch.
    assert_eq!(plan.releases().len(), 1);
    let release = &plan.releases()[0];
    assert_eq!(release.contract, contract_id("release-patch"));
    assert_eq!(
        release.destination,
        ContractDestination::External {
            target: tag("repo:acme-app:branch:fix-123")
        }
    );
    assert!(release.approval.is_operator());
    // 5. The narrow executor holds the credential and the effect, never untrusted code.
    let apply = plan.compartment_of(&step("apply")).unwrap();
    assert_eq!(
        apply.authorities,
        ops(&[credential("repo-token"), exact("release-patch")])
    );
    // Every crossing between compartments is under its contract.
    let between: Vec<(&DataId, Option<&ContractId>)> = plan
        .crossings()
        .iter()
        .filter(|crossing| crossing.from != CrossingSource::Source)
        .map(|crossing| (&crossing.item, crossing.contract.as_ref()))
        .collect();
    assert_eq!(
        between,
        vec![
            (&data("deps"), Some(&contract_id("deps-to-build"))),
            (&data("patch"), Some(&contract_id("patch-to-executor"))),
        ]
    );
    // The oracle finds the same partition: no other one is feasible.
    let (oracle, report) = compile_exhaustive(&workflow, &policy()).unwrap();
    assert_eq!(oracle.assignment(), plan.assignment());
    assert_eq!(oracle.cost(), plan.cost());
    assert_eq!(report.partitions, 5);
    assert_eq!(report.feasible, 1);
}

#[test]
fn the_objective_adds_startup_retention_transfer_delay_and_approvals() {
    // Worked numbers for the five-step plan with the fixture weights (line 2307):
    // fetch 2,000-32,000 ms, build 34,000-154,000 ms, apply 156,000-161,000 ms.
    let plan = compile(&valid(five_step()), &policy()).unwrap();
    let schedule: Vec<(u64, u64)> = plan
        .schedule()
        .iter()
        .map(|step| (step.start_ms, step.end_ms))
        .collect();
    assert_eq!(
        schedule,
        vec![(2_000, 32_000), (34_000, 154_000), (156_000, 161_000)]
    );
    let cost = plan.cost();
    assert_eq!(cost.makespan_ms, 161_000);
    assert_eq!(cost.vm_alive_ms, 32_000 + 122_000 + 7_000);
    // 64 KiB + 50 MiB + 200 MiB + 64 KiB = 250.125 MiB, rounded up per MiB.
    assert_eq!(cost.transferred_bytes, 262_275_072);
    assert_eq!(cost.startup_units, 3 * 100);
    assert_eq!(cost.retention_units, 161);
    assert_eq!(cost.transfer_units, 251);
    assert_eq!(cost.delay_units, 322);
    // The credential-holding executor plus the operator-approved release.
    assert_eq!(cost.approvals, 2);
    assert_eq!(cost.approval_units, 100);
    assert_eq!(
        cost.total_units,
        cost.startup_units
            + cost.retention_units
            + cost.transfer_units
            + cost.delay_units
            + cost.approval_units
    );
    assert_eq!(cost.total_units, 1_134);
}

#[test]
fn a_forbidden_combination_is_never_co_located() {
    let policy = policy();
    let five = valid(five_step());
    // Forcing any two conflicting steps together is refused by the constraint itself.
    let forced = partition_violations(&five, &policy, &[0, 0, 1]);
    assert!(forced.iter().any(|violation| matches!(
        violation,
        Violation::ForbiddenCombination { conflict, .. }
            if conflict.reason == ConflictReason::NameExfiltration
    )));
    let forced = partition_violations(&five, &policy, &[0, 1, 1]);
    assert!(forced.iter().any(|violation| matches!(
        violation,
        Violation::ForbiddenCombination { conflict, .. }
            if conflict.reason == ConflictReason::CredentialExposure
    )));
    // No plan from either method ever holds one, over many seeded workflows.
    let mut rng = SeededRng::new(0x5eed_0001);
    let mut plans = 0;
    for _ in 0..80 {
        let steps = 2 + rng.below(4) as usize;
        let Ok(workflow) = Workflow::new(random_workflow(&mut rng, steps)) else {
            continue;
        };
        for plan in [
            compile(&workflow, &policy).ok(),
            compile_exhaustive(&workflow, &policy)
                .ok()
                .map(|(plan, _)| plan),
        ]
        .into_iter()
        .flatten()
        {
            plans += 1;
            for compartment in plan.compartments() {
                assert!(policy
                    .conflicts
                    .conflicts(&compartment.authorities)
                    .is_empty());
                if !compartment.history.is_public() {
                    assert!(!compartment
                        .authorities
                        .iter()
                        .any(|authority| authority.is_unrestricted_release()));
                }
            }
        }
    }
    assert!(plans > 20, "{plans}");
}

#[test]
fn a_step_that_itself_needs_broad_private_release_is_explained_not_partitioned() {
    // Line 2338: mirroring a private repository to a public site needs private read and
    // arbitrary public write in one step.
    let spec = WorkflowSpec {
        sources: vec![private_source("project", "private-repo", MIB)],
        steps: vec![make_step(
            "mirror",
            &["project"],
            &[read("private-repo"), Authority::ArbitraryNetwork],
            Vec::new(),
            1_000,
            256,
        )],
        contracts: Vec::new(),
    };
    let workflow = valid(spec);
    let refusal = compile(&workflow, &policy()).unwrap_err();
    let CompileRefusal::BroadReleaseBoundary {
        step: refused,
        conflicts,
        secrecy,
        channels,
    } = &refusal
    else {
        panic!("{refusal:?}");
    };
    assert_eq!(refused, &step("mirror"));
    assert_eq!(conflicts[0].reason, ConflictReason::UnwantedRelease);
    assert_eq!(secrecy, &BTreeSet::from([tag("private-repo")]));
    assert_eq!(channels, &vec![Authority::ArbitraryNetwork]);
    let text = refusal.to_string();
    assert!(
        text.contains("legitimately needs broad private-data release"),
        "{text}"
    );
    assert!(text.contains("none is forced"), "{text}");
    // The oracle explains the same boundary instead of searching.
    assert_eq!(
        compile_exhaustive(&workflow, &policy()).unwrap_err(),
        refusal
    );
    // A public-posting step fed derived private data is the same boundary.
    let mut spec = five_step();
    spec.steps[2].operations = ops(&[Authority::ArbitraryNetwork]);
    spec.contracts.retain(|contract| !contract.is_external());
    let refusal = compile(&Workflow::new(spec).unwrap(), &policy()).unwrap_err();
    assert!(
        matches!(refusal, CompileRefusal::BroadReleaseBoundary { .. }),
        "{refusal:?}"
    );
}

#[test]
fn labels_stay_attached_to_derived_outputs_and_retained_state() {
    let mut spec = WorkflowSpec {
        sources: vec![private_source("secret", "repo", MIB)],
        steps: vec![
            make_step(
                "s1",
                &["secret"],
                &[read("repo")],
                vec![output("o1", KIB, false)],
                1_000,
                256,
            ),
            make_step(
                "s2",
                &["o1"],
                &[],
                vec![output("o2", KIB, true)],
                1_000,
                256,
            ),
            make_step(
                "s3",
                &["o2"],
                &[Authority::RunUntrustedCode],
                vec![output("o3", KIB, true)],
                1_000,
                256,
            ),
        ],
        contracts: Vec::new(),
    };
    spec.steps[0].volumes.insert(volume("cache"));
    let workflow = valid(spec.clone());
    let plan = compile(&workflow, &policy()).unwrap();
    for item in ["o1", "o2", "o3"] {
        assert_eq!(
            plan.labels()[&data(item)].secrecy(),
            &BTreeSet::from([tag("repo")]),
            "{item}"
        );
    }
    assert_eq!(plan.labels()[&data("o3")].integrity(), Integrity::Untrusted);
    assert_eq!(plan.labels()[&data("o2")].integrity(), Integrity::Trusted);
    // The retained volume carries the compartment's label, and keeps it across a restart.
    let mut run = PartitionRun::start(&workflow, &plan, &policy());
    let compartment = compartment_index(&plan, "s1");
    let label = run
        .volume_label(compartment, &volume("cache"))
        .unwrap()
        .clone();
    assert!(label.secrecy().contains(&tag("repo")));
    run.restart(compartment, RetainedState::Keep).unwrap();
    assert!(run
        .history(compartment)
        .unwrap()
        .secrecy()
        .contains(&tag("repo")));
    // A declared label can never remove a derived tag (line 2320).
    let mut lowered = spec;
    lowered.steps[1].outputs[0].declared_label =
        Some(Label::public(tag("public"), Integrity::Trusted));
    assert!(matches!(
        Workflow::new(lowered),
        Err(WorkflowError::DeclaredLabelBelowDerived { .. })
    ));
}

#[test]
fn a_model_assertion_is_never_a_label() {
    let mut spec = five_step();
    spec.sources[0].label = Label::public(tag("model-says-public"), Integrity::Trusted);
    spec.sources[0].origin = LabelOrigin::ModelAssertion {
        model: tag("assistant"),
    };
    let error = Workflow::new(spec).unwrap_err();
    assert_eq!(
        error,
        WorkflowError::ModelAssertedLabel {
            item: data("project"),
            model: tag("assistant"),
        }
    );
    assert!(error
        .to_string()
        .contains("trusted policy and explicit provenance"));
    assert!(!LabelOrigin::ModelAssertion {
        model: tag("assistant")
    }
    .is_accepted());
}

#[test]
fn history_blocks_later_network_authority() {
    let mut spec = WorkflowSpec {
        sources: vec![private_source("secret", "repo", MIB)],
        steps: vec![make_step(
            "reader",
            &["secret"],
            &[read("repo")],
            vec![output("summary", KIB, true)],
            1_000,
            256,
        )],
        contracts: Vec::new(),
    };
    spec.steps[0].volumes.insert(volume("scratch"));
    let workflow = valid(spec);
    let plan = compile(&workflow, &policy()).unwrap();
    let mut run = PartitionRun::start(&workflow, &plan, &policy());
    // Removing the read permission does not erase what was copied (line 2320).
    run.revoke(0, &read("repo")).unwrap();
    assert!(run.history(0).unwrap().secrecy().contains(&tag("repo")));
    assert!(matches!(
        run.grant(0, Authority::ArbitraryNetwork),
        Err(RunRefusal::HistoryForbidsRelease { .. })
    ));
    assert!(matches!(
        run.grant(0, Authority::RegistryFetch),
        Err(RunRefusal::HistoryForbidsRelease { .. })
    ));
    // Revocation is monotonic.
    assert!(matches!(
        run.grant(0, read("repo")),
        Err(RunRefusal::Revoked { .. })
    ));
    // A restart that keeps the volume keeps its history.
    assert_eq!(run.restart(0, RetainedState::Keep).unwrap(), 2);
    assert!(matches!(
        run.grant(0, Authority::ArbitraryNetwork),
        Err(RunRefusal::HistoryForbidsRelease { .. })
    ));
    // Only discarding the retained state gives a clean next generation.
    assert_eq!(run.restart(0, RetainedState::Discard).unwrap(), 3);
    assert!(run.history(0).unwrap().is_public());
    run.grant(0, Authority::ArbitraryNetwork).unwrap();
    assert!(run
        .emit(0, &Authority::ArbitraryNetwork)
        .unwrap()
        .is_public());
}

#[test]
fn a_dynamic_step_cannot_widen_rights() {
    let workflow = valid(five_step());
    let plan = compile(&workflow, &policy()).unwrap();
    let mut run = PartitionRun::start(&workflow, &plan, &policy());
    let build = compartment_index(&plan, "build");
    let callback =
        |id: &str, inputs: &[&str], operations: &[Authority], origin: DynamicOrigin| DynamicStep {
            step: make_step(
                id,
                inputs,
                operations,
                vec![output(&format!("{id}-out"), KIB, true)],
                1_000,
                256,
            ),
            origin,
            contracts: Vec::new(),
        };
    // A callback asking for network access its parent lacks is refused (line 2320).
    let refusal = run
        .add_step(callback(
            "cb",
            &["deps"],
            &[Authority::ArbitraryNetwork],
            DynamicOrigin::Callback { of: step("build") },
        ))
        .unwrap_err();
    assert_eq!(
        refusal,
        RunRefusal::CallbackWidensRights {
            step: step("cb"),
            parent: step("build"),
            beyond: vec![Authority::ArbitraryNetwork],
        }
    );
    // A loop iteration within its parent's rights runs in the parent's compartment.
    let placed = run
        .add_step(callback(
            "build-again",
            &["deps"],
            &[Authority::RunUntrustedCode],
            DynamicOrigin::LoopIteration { of: step("build") },
        ))
        .unwrap();
    assert_eq!(placed.compartment, build);
    assert!(!placed.new_compartment);
    assert!(run
        .label(&data("build-again-out"))
        .unwrap()
        .secrecy()
        .contains(&tag("private-repo")));
    // It cannot pull in data its parent's compartment does not hold, or bring contracts.
    assert!(matches!(
        run.add_step(callback(
            "loop-2",
            &["lockfile"],
            &[],
            DynamicOrigin::LoopIteration { of: step("build") },
        )),
        Err(RunRefusal::CallbackNeedsCrossing { .. })
    ));
    let mut with_contract = callback(
        "loop-3",
        &["deps"],
        &[],
        DynamicOrigin::Callback { of: step("build") },
    );
    with_contract.contracts.push(handoff(
        "loop-3-in",
        "deps",
        "loop-3",
        preauthorized("x"),
        MIB,
    ));
    assert!(matches!(
        run.add_step(with_contract),
        Err(RunRefusal::CallbackAddsContracts { .. })
    ));
    // After the parent's right is revoked, a repeat cannot use it either.
    run.revoke(build, &Authority::RunUntrustedCode).unwrap();
    assert!(matches!(
        run.add_step(callback(
            "build-3",
            &["deps"],
            &[Authority::RunUntrustedCode],
            DynamicOrigin::LoopIteration { of: step("build") },
        )),
        Err(RunRefusal::CallbackWidensRights { .. })
    ));
    // A new step that would post the private patch gets no compartment at all.
    let post = DynamicStep {
        step: make_step(
            "post",
            &["patch"],
            &[Authority::ArbitraryNetwork],
            Vec::new(),
            1_000,
            256,
        ),
        origin: DynamicOrigin::Added,
        contracts: vec![handoff(
            "patch-to-post",
            "patch",
            "post",
            preauthorized("x"),
            MIB,
        )],
    };
    let RunRefusal::NoPlacement { refused, .. } = run.add_step(post).unwrap_err() else {
        panic!("expected no placement");
    };
    assert_eq!(refused.len(), 4);
    for (_, violations) in &refused {
        assert!(violations
            .iter()
            .any(|violation| matches!(violation, Violation::HistoryForbidsRelease { .. })));
    }
    // A step needing a forbidden combination by itself is refused outright.
    assert!(matches!(
        run.add_step(callback(
            "both",
            &["deps"],
            &[read("private-repo"), Authority::ArbitraryNetwork],
            DynamicOrigin::Added,
        )),
        Err(RunRefusal::IntrinsicConflict { .. })
    ));
    // A harmless new step passes the same checks and joins the producer of its input.
    let lint = run
        .add_step(callback(
            "lint",
            &["deps"],
            &[Authority::RunUntrustedCode],
            DynamicOrigin::Added,
        ))
        .unwrap();
    assert_eq!(lint.compartment, compartment_index(&plan, "fetch"));
    assert!(!lint.explanation.lines().is_empty());
}

#[test]
fn persistent_state_cannot_smuggle_authority_into_a_later_generation() {
    // A step keeping a volume beside a credential is refused before partitioning.
    let mut spec = five_step();
    spec.steps[2].volumes.insert(volume("executor-cache"));
    let refusal = compile(&Workflow::new(spec).unwrap(), &policy()).unwrap_err();
    assert!(
        matches!(refusal, CompileRefusal::RetainedEffect { .. }),
        "{refusal:?}"
    );
    // Retained state shared by steps that must be separated has no feasible layout.
    let mut spec = WorkflowSpec {
        sources: vec![
            private_source("secret", "repo", MIB),
            public_source("open", "public", KIB),
        ],
        steps: vec![
            make_step(
                "fetch",
                &["open"],
                &[Authority::RegistryFetch],
                vec![output("pkg", KIB, true)],
                1_000,
                256,
            ),
            make_step(
                "use",
                &["secret"],
                &[read("repo")],
                vec![output("out", KIB, true)],
                1_000,
                256,
            ),
        ],
        contracts: Vec::new(),
    };
    spec.steps[0].volumes.insert(volume("shared"));
    spec.steps[1].volumes.insert(volume("shared"));
    let workflow = valid(spec);
    let CompileRefusal::NoPlacement { refused, .. } = compile(&workflow, &policy()).unwrap_err()
    else {
        panic!("expected no placement");
    };
    assert!(refused.iter().any(|(target, violations)| target.is_none()
        && violations
            .iter()
            .any(|violation| matches!(violation, Violation::RetainedStateSplit { .. }))));
    assert!(matches!(
        compile_exhaustive(&workflow, &policy()).unwrap_err(),
        CompileRefusal::NoFeasiblePartition { .. }
    ));
    // At run time an effect is never granted beside retained state.
    let mut spec = WorkflowSpec {
        sources: vec![public_source("open", "public", KIB)],
        steps: vec![make_step(
            "work",
            &["open"],
            &[],
            vec![output("w", KIB, true)],
            1_000,
            256,
        )],
        contracts: Vec::new(),
    };
    spec.steps[0].volumes.insert(volume("state"));
    let workflow = valid(spec);
    let plan = compile(&workflow, &policy()).unwrap();
    let mut run = PartitionRun::start(&workflow, &plan, &policy());
    assert!(matches!(
        run.grant(0, credential("repo-token")),
        Err(RunRefusal::AuthorityPersisted { .. })
    ));
    // A restart never restores authority and keeps revocations.
    run.grant(0, Authority::ApprovedContent).unwrap();
    run.revoke(0, &Authority::ApprovedContent).unwrap();
    run.restart(0, RetainedState::Keep).unwrap();
    assert!(!run
        .authorities(0)
        .unwrap()
        .contains(&Authority::ApprovedContent));
    assert!(matches!(
        run.grant(0, Authority::ApprovedContent),
        Err(RunRefusal::Revoked { .. })
    ));
}

#[test]
fn data_crossing_a_boundary_needs_an_explicit_contract() {
    let mut spec = five_step();
    spec.contracts
        .retain(|contract| contract.id != contract_id("deps-to-build"));
    let workflow = valid(spec);
    let refusal = compile(&workflow, &policy()).unwrap_err();
    let CompileRefusal::NoPlacement {
        step: refused,
        refused: reasons,
    } = &refusal
    else {
        panic!("{refusal:?}");
    };
    assert_eq!(refused, &step("build"));
    assert!(reasons.iter().any(|(target, violations)| target.is_none()
        && violations
            .iter()
            .any(|violation| matches!(violation, Violation::CrossingWithoutContract { .. }))));
    assert!(refusal.to_string().contains("without a release contract"));
    // A contract too small for the item is refused too.
    let mut spec = five_step();
    spec.contracts[0].max_bytes = MIB;
    let refusal = compile(&Workflow::new(spec).unwrap(), &policy()).unwrap_err();
    assert!(
        refusal.to_string().contains("allows 1048576 bytes"),
        "{refusal}"
    );
}

#[test]
fn every_plan_and_refusal_carries_an_explanation() {
    let plan = compile(&valid(five_step()), &policy()).unwrap();
    let reasons = plan.explanation().reasons();
    assert!(reasons.iter().any(|reason| matches!(
        reason,
        Reason::Separated { left, right, conflict }
            if left == &step("fetch") && right == &step("build")
                && conflict.reason == ConflictReason::NameExfiltration
    )));
    assert!(reasons.iter().any(|reason| matches!(
        reason,
        Reason::Separated { conflict, .. } if conflict.reason == ConflictReason::CredentialExposure
    )));
    assert!(reasons.iter().any(|reason| matches!(
        reason,
        Reason::SeparatedByHistory { private_step, release_step, .. }
            if private_step == &step("apply") && release_step == &step("fetch")
    )));
    assert_eq!(
        reasons
            .iter()
            .filter(|reason| matches!(reason, Reason::HistoryAccounted { .. }))
            .count(),
        2
    );
    assert_eq!(
        reasons
            .iter()
            .filter(|reason| matches!(reason, Reason::Placed { .. }))
            .count(),
        3
    );
    let lines = plan.explanation().lines();
    assert!(lines
        .iter()
        .any(|line| line.contains("the approval is not a proof of confidentiality")));
    // A plan that requests approved objects from a private compartment names the
    // metadata channel.
    let lazy = compile(&valid(lazy_build()), &policy()).unwrap();
    assert!(lazy
        .explanation()
        .reasons()
        .iter()
        .any(|reason| matches!(reason, Reason::MetadataChannel { .. })));
    assert!(lazy
        .explanation()
        .lines()
        .iter()
        .any(|line| line.contains("not noninterference")));
    // The oracle's refusal explains the extremes.
    let mut spec = five_step();
    spec.contracts.clear();
    spec.steps[2].operations = ops(&[credential("repo-token")]);
    let refusal = compile_exhaustive(&Workflow::new(spec).unwrap(), &policy()).unwrap_err();
    let CompileRefusal::NoFeasiblePartition {
        single_vm,
        one_vm_per_step,
        ..
    } = &refusal
    else {
        panic!("{refusal:?}");
    };
    assert!(!single_vm.is_empty() && !one_vm_per_step.is_empty());
    assert!(!refusal.to_string().is_empty());
}

#[test]
fn approval_authorizes_an_exact_release_and_proves_no_confidentiality() {
    let workflow = valid(five_step());
    let plan = compile(&workflow, &policy()).unwrap();
    let apply = compartment_index(&plan, "apply");
    let build = compartment_index(&plan, "build");
    let approved = ContentKey::of(b"patch v1");
    let changed = ContentKey::of(b"patch v2");
    let release = contract_id("release-patch");
    let mut run = PartitionRun::start(&workflow, &plan, &policy());
    assert!(matches!(
        run.release(apply, &release, approved, 100),
        Err(RunRefusal::NotBound { .. })
    ));
    run.bind_release(&release, approved).unwrap();
    assert!(matches!(
        run.bind_release(&release, changed),
        Err(RunRefusal::AlreadyBound { .. })
    ));
    assert!(matches!(
        run.release(build, &release, approved, 100),
        Err(RunRefusal::NotHeld { .. })
    ));
    assert_eq!(
        run.release(apply, &release, changed, 100).unwrap_err(),
        RunRefusal::ContentChanged {
            contract: release.clone(),
            bound: approved,
            presented: changed,
        }
    );
    assert!(matches!(
        run.release(apply, &release, approved, 2 * MIB),
        Err(RunRefusal::TooLarge { .. })
    ));
    let record = run.release(apply, &release, approved, 64 * KIB).unwrap();
    assert!(record.approval.is_operator());
    assert_eq!(record.confidentiality, ConfidentialityStatus::NotProven);
    assert!(record.label.secrecy().contains(&tag("private-repo")));
    assert_eq!(run.release_budget().released_bytes(), 64 * KIB);
    assert!(matches!(
        run.release(apply, &release, approved, 64 * KIB),
        Err(RunRefusal::AlreadyReleased { .. })
    ));
    // An internal contract cannot be bound for release.
    assert!(matches!(
        run.bind_release(&contract_id("deps-to-build"), approved),
        Err(RunRefusal::NotExternal { .. })
    ));
    assert_eq!(
        operator().confidentiality(),
        ConfidentialityStatus::NotProven
    );
    assert_eq!(
        preauthorized("x").confidentiality(),
        ConfidentialityStatus::NotProven
    );
}

#[test]
fn the_rules_never_beat_the_oracle_on_seeded_small_workflows() {
    let policy = policy();
    let mut rng = SeededRng::new(0x0bad_cafe);
    let (mut compared, mut oracle_better, mut rules_refused_oracle_found) = (0, 0, 0);
    for _ in 0..60 {
        let steps = 2 + rng.below(4) as usize;
        let Ok(workflow) = Workflow::new(random_workflow(&mut rng, steps)) else {
            continue;
        };
        let rules = compile(&workflow, &policy);
        let oracle = compile_exhaustive(&workflow, &policy);
        match (rules, oracle) {
            (Ok(rules), Ok((oracle, report))) => {
                compared += 1;
                assert!(oracle.cost().total_units <= rules.cost().total_units);
                assert!(report.feasible >= 1);
                if oracle.cost().total_units < rules.cost().total_units {
                    oracle_better += 1;
                }
            }
            (Ok(rules), Err(refusal)) => panic!("rules found {rules:?}; oracle refused {refusal}"),
            (Err(_), Ok(_)) => rules_refused_oracle_found += 1,
            (Err(rules), Err(oracle)) => {
                // Both refuse; a step-level boundary is refused identically.
                if matches!(rules, CompileRefusal::BroadReleaseBoundary { .. }) {
                    assert_eq!(rules, oracle);
                }
            }
        }
    }
    assert!(compared >= 15, "{compared}");
    let _ = (oracle_better, rules_refused_oracle_found);
}

#[test]
fn the_rules_are_not_optimal_in_general() {
    // Line 2318: no universal optimality claim. Joining any existing compartment loses
    // parallelism when delay is weighted heavily.
    let spec = WorkflowSpec {
        sources: Vec::new(),
        steps: vec![
            make_step("a", &[], &[], vec![output("oa", KIB, true)], 10_000, 256),
            make_step(
                "b",
                &["oa"],
                &[],
                vec![output("ob", KIB, true)],
                10_000,
                256,
            ),
            make_step("c", &[], &[], vec![output("oc", KIB, true)], 100_000, 256),
        ],
        contracts: Vec::new(),
    };
    let workflow = valid(spec);
    let mut policy = policy();
    policy.weights.delay_units_per_second = 10;
    let rules = compile(&workflow, &policy).unwrap();
    let (oracle, _) = compile_exhaustive(&workflow, &policy).unwrap();
    // Rules: one VM, 2 s boot + 120 s: 100 + 122 + 1,220 = 1,442.
    assert_eq!(rules.cost().total_units, 1_442);
    assert_eq!(rules.compartments().len(), 1);
    // Oracle: {a, b} and {c} in parallel, 102 s: 200 + 124 + 1,020 = 1,344.
    assert_eq!(oracle.cost().total_units, 1_344);
    assert_eq!(oracle.compartments().len(), 2);
    assert_eq!(rules.method(), &PartitionMethod::RulesBased);
    assert!(matches!(
        oracle.method(),
        PartitionMethod::ExhaustiveOracle { .. }
    ));
}

#[test]
fn the_oracle_is_bounded_to_small_workflows() {
    let steps: Vec<Step> = (0..=ORACLE_MAX_STEPS)
        .map(|index| make_step(&format!("s{index}"), &[], &[], Vec::new(), 1_000, 256))
        .collect();
    let workflow = valid(WorkflowSpec {
        sources: Vec::new(),
        steps,
        contracts: Vec::new(),
    });
    assert_eq!(
        compile_exhaustive(&workflow, &policy()).unwrap_err(),
        CompileRefusal::TooLargeForOracle {
            steps: ORACLE_MAX_STEPS + 1,
            max: ORACLE_MAX_STEPS,
        }
    );
    // The rules still handle it.
    assert!(compile(&workflow, &policy()).is_ok());
    assert_eq!(super::oracle::set_partitions(5).len(), 52);
    assert_eq!(super::oracle::set_partitions(7).len(), 877);
}

#[test]
fn model6_private_inputs_reach_no_unrestricted_output_without_a_contract() {
    let policy = model_policy();
    let acceptor = plan_acceptor(&policy);
    let report = check_model6(ModelBounds::full(), &acceptor).unwrap();
    assert_eq!(report.violations, 0, "{:?}", report.counterexamples);
    // Workflows enumerated, from the model's definition: step i chooses 2^(i+1) input
    // sets and 4 operations, and each of its edges from earlier items may carry a
    // contract; summing 2^(edges) over its input sets gives 2 * 3^i, so step i
    // contributes 8 * 3^i. One step: 8; two: 8 * 24 = 192; three: 8 * 24 * 72 = 13,824.
    assert_eq!(report.workflows, 8 + 192 + 13_824);
    assert!(report.accepted > 0, "{report:?}");
    assert!(report.candidates > report.accepted);
    assert!(report.rejected_workflows > 0);
    assert_eq!(report.bounds.max_steps, MODEL6_MAX_STEPS);
    // A weakened acceptor that ignores history finds counterexamples, so the property is
    // not vacuous; each is refused by the real compiler.
    let ignore_history = |workflow: &Workflow, assignment: &[u32], order: &[usize]| {
        analyze(workflow, &policy, assignment, order)
            .violations
            .iter()
            .all(|violation| matches!(violation, Violation::HistoryForbidsRelease { .. }))
    };
    let weakened = check_model6(ModelBounds::full(), &ignore_history).unwrap();
    assert!(weakened.violations > 0);
    for counterexample in &weakened.counterexamples {
        let workflow = Workflow::new(counterexample.spec.clone()).unwrap();
        // The workflow may have another, safe partition; whatever the compiler chooses
        // never puts private data beside an unrestricted channel.
        let plans = [
            compile(&workflow, &policy).ok(),
            compile_exhaustive(&workflow, &policy)
                .ok()
                .map(|(plan, _)| plan),
        ];
        for plan in plans.into_iter().flatten() {
            for compartment in plan.compartments() {
                assert!(
                    compartment.history.is_public()
                        || !compartment
                            .authorities
                            .iter()
                            .any(|authority| authority.is_unrestricted_release())
                );
            }
        }
        let order: Vec<usize> = counterexample
            .order
            .iter()
            .map(|id| workflow.index_of(id).unwrap())
            .collect();
        assert!(!acceptor(&workflow, &counterexample.assignment, &order));
    }
    // Ignoring contract coverage is caught too.
    let ignore_contracts = |workflow: &Workflow, assignment: &[u32], order: &[usize]| {
        analyze(workflow, &policy, assignment, order)
            .violations
            .iter()
            .all(|violation| matches!(violation, Violation::CrossingWithoutContract { .. }))
    };
    let weakened = check_model6(ModelBounds::full(), &ignore_contracts).unwrap();
    assert!(weakened.violations > 0);
    assert!(weakened.counterexamples[0]
        .detail
        .contains("without a declared contract"));
    assert!(check_model6(ModelBounds { max_steps: 4 }, &acceptor).is_err());
}

#[test]
fn vm_d12_lifetimes_and_the_release_budget_are_enforced() {
    assert_eq!(VM_D12_TASK_IDLE_MS, 43_200_000);
    assert_eq!(VM_D12_TASK_ABSOLUTE_MS, 86_400_000);
    assert_eq!(VM_D12_GENERAL_RELEASE_BUDGET_BYTES, 8_388_608);
    let budgets = Budgets::with_vm_d12_lifetimes(4, 4, 1 << 20, 0);
    assert_eq!(budgets.max_vm_idle_ms, VM_D12_TASK_IDLE_MS);
    assert_eq!(budgets.max_vm_lifetime_ms, VM_D12_TASK_ABSOLUTE_MS);
    assert_eq!(
        budgets.release_budget_bytes,
        VM_D12_GENERAL_RELEASE_BUDGET_BYTES
    );
    // A 25-hour step outlives a task sandbox.
    let long = valid(WorkflowSpec {
        sources: Vec::new(),
        steps: vec![make_step("long", &[], &[], Vec::new(), 25 * 3_600_000, 256)],
        contracts: Vec::new(),
    });
    let refusal = compile(&long, &policy()).unwrap_err();
    assert!(matches!(
        &refusal,
        CompileRefusal::Infeasible { violations }
            if matches!(violations[0], Violation::LifetimeExceeded { .. })
    ));
    // A compartment idling 13 hours while another runs exceeds the idle limit.
    let idle = valid(WorkflowSpec {
        sources: Vec::new(),
        steps: vec![
            make_step("a", &[], &[], vec![output("oa", KIB, true)], 1_000, 256),
            make_step(
                "b",
                &["oa"],
                &[],
                vec![output("ob", KIB, true)],
                13 * 3_600_000,
                256,
            ),
            make_step("c", &["ob"], &[], Vec::new(), 1_000, 256),
        ],
        contracts: vec![
            handoff("oa-to-b", "oa", "b", preauthorized("x"), MIB),
            handoff("ob-to-c", "ob", "c", preauthorized("x"), MIB),
        ],
    });
    let analysis = analyze(&idle, &policy(), &[0, 1, 0], &[0, 1, 2]);
    assert!(analysis
        .violations
        .iter()
        .any(|violation| matches!(violation, Violation::IdleExceeded { compartment: 0, .. })));
    // A 9 MiB release exceeds the 8 MiB general release budget.
    let mut spec = five_step();
    spec.steps[1].outputs[0].size_bytes = 9 * MIB;
    for contract in &mut spec.contracts {
        contract.max_bytes = contract.max_bytes.max(16 * MIB);
    }
    let refusal = compile(&Workflow::new(spec).unwrap(), &policy()).unwrap_err();
    assert!(matches!(
        &refusal,
        CompileRefusal::Infeasible { violations } if violations.contains(&Violation::ReleaseBudgetExceeded {
            bytes: 9 * MIB,
            limit_bytes: VM_D12_GENERAL_RELEASE_BUDGET_BYTES,
        })
    ));
}

#[test]
fn vm_count_concurrency_and_memory_budgets_stay_feasible() {
    let five = valid(five_step());
    let mut tight = policy();
    tight.budgets.max_vms = 2;
    assert!(matches!(
        compile(&five, &tight).unwrap_err(),
        CompileRefusal::Infeasible { violations }
            if violations.contains(&Violation::TooManyVms { vms: 3, max: 2 })
    ));
    let mut small = policy();
    small.budgets.host_memory_mib = 4_000;
    assert!(matches!(
        compile(&five, &small).unwrap_err(),
        CompileRefusal::Infeasible { violations }
            if violations.iter().any(|violation| matches!(violation, Violation::MemoryExceeded { needed_mib: 4_608, .. }))
    ));
    let parallel = valid(WorkflowSpec {
        sources: Vec::new(),
        steps: vec![
            make_step("x", &[], &[], Vec::new(), 1_000, 256),
            make_step("y", &[], &[], Vec::new(), 1_000, 256),
        ],
        contracts: Vec::new(),
    });
    let mut serial = policy();
    serial.budgets.max_concurrent_vms = 1;
    let analysis = analyze(&parallel, &serial, &[0, 1], &[0, 1]);
    assert!(analysis.violations.iter().any(|violation| matches!(
        violation,
        Violation::TooManyConcurrentVms { vms: 2, max: 1, .. }
    )));
    // The oracle then keeps both in one VM.
    let (plan, _) = compile_exhaustive(&parallel, &serial).unwrap();
    assert_eq!(plan.compartments().len(), 1);
}

#[test]
fn unavailable_actions_are_refused() {
    let mut no_network = policy();
    no_network.grantable.remove(&AuthorityKind::RegistryFetch);
    assert_eq!(
        compile(&valid(five_step()), &no_network).unwrap_err(),
        CompileRefusal::NotGrantable {
            step: step("fetch"),
            authority: Authority::RegistryFetch,
        }
    );
    let mut zero = policy();
    zero.weights.transfer_bytes_per_ms = 0;
    assert_eq!(
        compile(&valid(five_step()), &zero).unwrap_err(),
        CompileRefusal::InvalidWeights
    );
}

#[test]
fn workflow_validation_refuses_malformed_dags_and_contracts() {
    let mut cyclic = five_step();
    cyclic.steps[0].inputs.push(data("patch"));
    assert!(matches!(
        Workflow::new(cyclic),
        Err(WorkflowError::Cycle { .. })
    ));
    let mut unknown = five_step();
    unknown.steps[0].inputs.push(data("nowhere"));
    assert!(matches!(
        Workflow::new(unknown),
        Err(WorkflowError::UnknownInput { .. })
    ));
    let mut unread = five_step();
    unread.steps[1].operations.remove(&read("private-repo"));
    assert!(matches!(
        Workflow::new(unread),
        Err(WorkflowError::PrivateSourceWithoutReadAuthority { .. })
    ));
    let mut source_contract = five_step();
    source_contract
        .contracts
        .push(handoff("p", "project", "build", preauthorized("x"), MIB));
    assert!(matches!(
        Workflow::new(source_contract),
        Err(WorkflowError::ContractForSource { .. })
    ));
    let mut unused = five_step();
    unused.steps[2].operations.remove(&exact("release-patch"));
    assert!(matches!(
        Workflow::new(unused),
        Err(WorkflowError::ExternalContractUnused { .. })
    ));
    let mut internal = five_step();
    internal.steps[2]
        .operations
        .insert(exact("patch-to-executor"));
    assert!(matches!(
        Workflow::new(internal),
        Err(WorkflowError::ExactReleaseOnInternalContract { .. })
    ));
    let mut mutable = five_step();
    mutable.steps[1].outputs[0].immutable = false;
    assert!(matches!(
        Workflow::new(mutable),
        Err(WorkflowError::ReleaseOfMutableItem { .. })
    ));
    let mut duplicate = five_step();
    duplicate
        .contracts
        .push(handoff("again", "deps", "build", preauthorized("x"), MIB));
    assert!(matches!(
        Workflow::new(duplicate),
        Err(WorkflowError::ConflictingContracts { .. })
    ));
    let empty = WorkflowSpec {
        sources: Vec::new(),
        steps: Vec::new(),
        contracts: Vec::new(),
    };
    assert_eq!(Workflow::new(empty), Err(WorkflowError::NoSteps));
}

#[test]
fn serialized_specs_are_read_strictly() {
    let spec = five_step();
    let json = serde_json::to_string(&spec).unwrap();
    let read_back: WorkflowSpec = serde_json::from_str(&json).unwrap();
    assert_eq!(read_back, spec);
    assert_eq!(
        Workflow::new(read_back).unwrap().digest(),
        valid(five_step()).digest()
    );
    for text in [
        r#"{"authority":"run_untrusted_code","extra":1}"#,
        r#"{"authority":"read_private","source":"repo","extra":1}"#,
        r#"{"authority":"anything_goes"}"#,
    ] {
        assert!(serde_json::from_str::<Authority>(text).is_err(), "{text}");
    }
    assert!(serde_json::from_str::<Label>(
        r#"{"secrecy":[],"provenance":[],"integrity":"trusted","harmless":true}"#
    )
    .is_err());
    assert!(
        serde_json::from_str::<LabelOrigin>(r#"{"origin":"trusted_policy","rule":"r","x":1}"#)
            .is_err()
    );
    assert!(serde_json::from_str::<Approval>(
        r#"{"approval":"operator","reviewer":"a","proof":true}"#
    )
    .is_err());
}

#[test]
fn compartments_are_distinct_trust_scopes() {
    let plan = compile(&valid(five_step()), &policy()).unwrap();
    let scopes: BTreeSet<_> = plan
        .compartments()
        .iter()
        .map(|compartment| compartment.trust_scope)
        .collect();
    assert_eq!(scopes.len(), 3);
    assert!(plan
        .compartments()
        .iter()
        .all(|compartment| compartment.trust_scope.category.is_vm_sandbox()));
}

#[test]
fn the_comparison_is_recorded_with_fake_substrate_provenance() {
    let mut cases = Vec::new();
    for (spec, malicious) in [
        (five_step(), vec!["fetch", "build"]),
        (research(), vec!["gather", "analyze"]),
        (lazy_build(), vec!["build"]),
    ] {
        cases.push((
            valid(spec),
            AttackPlan {
                malicious: malicious.into_iter().map(step).collect(),
            },
        ));
    }
    let arms = compare_arms(&cases, &policy());
    let get = |arm: Arm| arms.iter().find(|metrics| metrics.arm == arm).unwrap();
    let broad = get(Arm::BroadVm);
    let manual = get(Arm::ManualSeparation);
    let compiler = get(Arm::Compiler);
    assert_eq!(
        (broad.vm_count, manual.vm_count, compiler.vm_count),
        (3, 8, 7)
    );
    assert_eq!(compiler.completed, 3);
    // Permission breadth: the broad VM holds every forbidden pair; the compiler none.
    assert_eq!(broad.forbidden_combinations, 6);
    assert_eq!(manual.forbidden_combinations, 1);
    assert_eq!(compiler.forbidden_combinations, 0);
    assert!(compiler.max_authorities_per_vm < broad.max_authorities_per_vm);
    // Malicious outputs: three unsafe attempts per arm, blocked 1, 2 and 3 times.
    assert_eq!(
        (broad.unsafe_release_attempts, broad.unsafe_releases_blocked),
        (3, 1)
    );
    assert_eq!(
        (
            manual.unsafe_release_attempts,
            manual.unsafe_releases_blocked
        ),
        (3, 2)
    );
    assert_eq!(
        (
            compiler.unsafe_release_attempts,
            compiler.unsafe_releases_blocked
        ),
        (3, 3)
    );
    // Cross-stage persistence: shared state lets every attempt through except under the
    // compiler.
    assert_eq!(
        (broad.persistence_attempts, broad.persistence_blocked),
        (4, 0)
    );
    assert_eq!(
        (manual.persistence_attempts, manual.persistence_blocked),
        (4, 0)
    );
    assert_eq!(
        (compiler.persistence_attempts, compiler.persistence_blocked),
        (4, 4)
    );
    assert_eq!(
        (broad.approvals, manual.approvals, compiler.approvals),
        (4, 10, 5)
    );
    assert!(broad.modelled_latency_ms > 0 && compiler.modelled_latency_ms > 0);
    // Recorded under the fake-substrate provenance; it backs no claim.
    let record = ComparisonRecord::new(&[fake_run()], cases.len() as u32, arms.clone()).unwrap();
    assert!(record.provenance().is_fake_substrate());
    assert_eq!(
        record.claim_evidence(),
        Err(ReportError::FakeSubstrateIsNotEvidence)
    );
    assert_eq!(record.arm(Arm::Compiler), Some(compiler));
    assert_eq!(
        ComparisonRecord::new(&[measured_run()], 3, arms.clone()).unwrap_err(),
        ComparisonError::NotFakeSubstrate
    );
    assert!(matches!(
        ComparisonRecord::new(&[], 3, arms),
        Err(ComparisonError::Report(ReportError::NoAttempts))
    ));
    // The novelty records are at most inconclusive on fakes (§9.5).
    let records = novelty_records(Some(&record));
    assert_eq!(records.len(), 2);
    assert!(records
        .iter()
        .all(|record| record.result == ClaimResult::InconclusiveOnFakes));
    assert!(novelty_records(None)
        .iter()
        .all(|record| record.result == ClaimResult::NotEvaluated));
}
