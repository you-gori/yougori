//! A shared GPU's release by process exit, gated by the host's proof (S04): the plain
//! release by process exit is refused; the proof must be of the process the binding
//! table holds for the runner of each activation that holds the memory, or, without
//! model memory, for the execution's VM; and a stray process's proof, the old process of
//! a role bound again to a replacement, a replacement runner's proof alone, another
//! role's proof and a VM's proof for model memory are each refused with a typed reason,
//! releasing nothing.

use super::*;
use crate::foundation::coordination::{
    ActivationState, CancellationBoundary, ExitRefusal, GpuAssignment, ReleaseMechanism,
    ReturnRefusal, ReturnStage,
};

/// Runtime settings under the execution's current authority.
fn settings(world: &World, of: &ExecutionId) -> RuntimeSettings {
    RuntimeSettings {
        execution_category: ExecutionCategory::VmSandbox,
        network: BTreeSet::new(),
        authority: world.coordinator.sandbox(of).unwrap().authority().unwrap(),
        artifact_verification: ArtifactVerification::Verified {
            artifacts: BTreeSet::new(),
        },
        loader: BTreeSet::new(),
        batch_size: NonZeroU32::new(8).unwrap(),
        residency: Residency::Device,
    }
}

/// Begins an activation of the test model with 2 GiB of GPU memory, completing it when
/// `complete`; returns its generations.
fn activate(world: &mut World, of: &ExecutionId, complete: bool) -> ModelGenerations {
    let settings = settings(world, of);
    let handle = world
        .coordinator
        .begin_activation(
            of,
            model(),
            settings,
            GpuDemand {
                device: device(),
                memory_bytes: 2 * GIB,
            },
        )
        .unwrap();
    if complete {
        world
            .coordinator
            .complete_activation(of, model(), handle.generations.activation)
            .unwrap();
    }
    handle.generations
}

/// Begins the owner's return of the shared GPU; no work is in flight, so it is drained.
fn begin_return(world: &mut World, of: &ExecutionId) {
    assert_eq!(
        world.coordinator.begin_resource_return(
            of,
            GpuAssignment::Shared,
            BTreeSet::from([CancellationBoundary::BetweenRequests]),
            BTreeSet::from([ResourceKind::GpuMemoryBytes { device: device() }]),
        ),
        Ok(ReturnStage::WorkStopped)
    );
}

fn exit_refused(refusal: ExitRefusal) -> ReturnRefusal {
    ReturnRefusal::ProcessExit { refusal }
}

fn runner(of: &ExecutionId, generations: ModelGenerations) -> ProcessRole {
    ProcessRole::ModelRunner {
        execution: of.clone(),
        model: model(),
        generations,
    }
}

/// The proof of a process bound for `role` in a table of its own, which ended at once.
fn bound_elsewhere(role: ProcessRole) -> (RunnerProcesses, TerminationProof) {
    let mut table = RunnerProcesses::new();
    table.bind(spawn("exit:0", role.clone())).unwrap();
    let proof = table.process(&role).unwrap().wait_ended(PATIENT).unwrap();
    (table, proof)
}

fn returned(world: &World, of: &ExecutionId) -> bool {
    world
        .coordinator
        .resource_return(of)
        .is_some_and(|operation| operation.stage() == ReturnStage::Released)
}

#[test]
fn a_shared_gpu_returns_by_process_exit_only_on_the_proof_of_its_bound_runner() {
    let mut world = World::new();
    let of = execution("exe-exit-release");
    let mut backend = HelperVms::new(&["sleep"]);
    let vm = world.launched(&of, &mut backend);
    world.coordinator.start_running(&of).unwrap();
    let generations = activate(&mut world, &of, true);
    begin_return(&mut world, &of);

    // A process exit is no longer taken on the caller's word.
    assert_eq!(
        world
            .coordinator
            .release_resource(&of, ReleaseMechanism::ProcessExit),
        Err(exit_refused(ExitRefusal::ProofRequired))
    );
    let role = runner(&of, generations);
    let mut runners = RunnerProcesses::new();
    runners.bind(spawn("sleep", role.clone())).unwrap();
    assert_eq!(
        world
            .coordinator
            .release_resource_on_exit(&of, &runners, &[]),
        Err(exit_refused(ExitRefusal::RunnerNotProven {
            model: model(),
            generations
        }))
    );

    // A process started for the runner's role but never bound: its end proves nothing.
    let stray = spawn("exit:0", role.clone()).wait_ended(PATIENT).unwrap();
    assert_eq!(
        world
            .coordinator
            .release_resource_on_exit(&of, &runners, &[&stray]),
        Err(exit_refused(ExitRefusal::NotTheBoundProcess {
            identity: stray.identity()
        }))
    );
    // Bound runners of another execution, and of generations this one never activated.
    let elsewhere = runner_role("exe-other", 1);
    let (other_table, other_proof) = bound_elsewhere(elsewhere.clone());
    assert_eq!(
        world
            .coordinator
            .release_resource_on_exit(&of, &other_table, &[&other_proof]),
        Err(exit_refused(ExitRefusal::OtherRole { role: elsewhere }))
    );
    let unknown = runner(&of, super::generations(9, 9));
    let (unknown_table, unknown_proof) = bound_elsewhere(unknown.clone());
    assert_eq!(
        world
            .coordinator
            .release_resource_on_exit(&of, &unknown_table, &[&unknown_proof]),
        Err(exit_refused(ExitRefusal::OtherRole { role: unknown }))
    );
    // The VM's host process ended, as the host observed, but the model memory is the
    // runner's: the VM's end never settles it.
    let vm_proof = backend
        .processes
        .process(&vm)
        .unwrap()
        .terminate(kill_now())
        .unwrap();
    assert_eq!(
        world
            .coordinator
            .release_resource_on_exit(&of, &backend.processes, &[&vm_proof]),
        Err(exit_refused(ExitRefusal::OtherAuthority {
            role: vm_proof.role().clone()
        }))
    );

    // The bound runner ended, and a replacement process was bound to the same role: the
    // old process's proof binds no more, because the replacement may hold the memory now.
    let old_proof = runners
        .process(&role)
        .unwrap()
        .terminate(kill_now())
        .unwrap();
    runners.bind(spawn("sleep", role.clone())).unwrap();
    assert_eq!(
        world
            .coordinator
            .release_resource_on_exit(&of, &runners, &[&old_proof]),
        Err(exit_refused(ExitRefusal::NotTheBoundProcess {
            identity: old_proof.identity()
        }))
    );
    // Nothing was released by any refusal.
    assert!(!returned(&world, &of));
    let activations = world.coordinator.model_activations(&of, model()).unwrap();
    assert_eq!(
        activations.activations()[0].state(),
        ActivationState::Active
    );
    assert!(activations.activations()[0].gpu_reservation_counted());

    // The proof of the process bound to the role now releases the memory, as the host
    // observed it.
    let proof = runners
        .process(&role)
        .unwrap()
        .terminate(kill_now())
        .unwrap();
    let measured = world
        .coordinator
        .release_resource_on_exit(&of, &runners, &[&proof])
        .unwrap();
    assert!(measured.vram_release.is_some());
    let activations = world.coordinator.model_activations(&of, model()).unwrap();
    assert!(activations.activations()[0].state().is_retired());
    assert!(!activations.activations()[0].gpu_reservation_counted());
    assert!(closed_on_host_observation(world.coordinator.capacity()));
    assert_eq!(
        world
            .coordinator
            .finish_resource_return(&of)
            .map(|report| report.mechanism),
        Ok(ReleaseMechanism::ProcessExit)
    );
}

#[test]
fn a_replacement_runners_proof_alone_never_releases_the_old_runners_memory() {
    let mut world = World::new();
    let of = execution("exe-exit-replacement");
    let mut backend = HelperVms::new(&["sleep"]);
    world.launched(&of, &mut backend);
    world.coordinator.start_running(&of).unwrap();
    // The old generation serves while its replacement loads beside it.
    let old = activate(&mut world, &of, true);
    let new = activate(&mut world, &of, false);
    begin_return(&mut world, &of);
    let mut runners = RunnerProcesses::new();
    runners.bind(spawn("sleep", runner(&of, old))).unwrap();
    runners.bind(spawn("sleep", runner(&of, new))).unwrap();

    let new_proof = runners
        .process(&runner(&of, new))
        .unwrap()
        .terminate(kill_now())
        .unwrap();
    assert_eq!(
        world
            .coordinator
            .release_resource_on_exit(&of, &runners, &[&new_proof]),
        Err(exit_refused(ExitRefusal::RunnerNotProven {
            model: model(),
            generations: old
        }))
    );
    assert!(!returned(&world, &of));

    let old_proof = runners
        .process(&runner(&of, old))
        .unwrap()
        .terminate(kill_now())
        .unwrap();
    assert!(world
        .coordinator
        .release_resource_on_exit(&of, &runners, &[&new_proof, &old_proof])
        .is_ok());
    let activations = world.coordinator.model_activations(&of, model()).unwrap();
    assert!(
        activations
            .activations()
            .iter()
            .all(|activation| activation.state().is_retired()
                && !activation.gpu_reservation_counted())
    );
}

#[test]
fn without_model_memory_only_the_bound_vm_host_process_exit_releases_a_shared_gpu() {
    let mut world = World::new();
    let of = execution("exe-exit-vm");
    let mut backend = HelperVms::new(&["sleep"]);
    let vm = world.launched(&of, &mut backend);
    world.coordinator.start_running(&of).unwrap();
    begin_return(&mut world, &of);
    let boot = SandboxBootGeneration::FIRST;
    assert_eq!(
        world
            .coordinator
            .release_resource_on_exit(&of, &backend.processes, &[]),
        Err(exit_refused(ExitRefusal::VmNotProven {
            vm: Some(vm),
            boot
        }))
    );
    // A second process started for the VM's role is not the one the table holds.
    let stray = spawn("exit:0", vm_role("exe-exit-vm"))
        .wait_ended(PATIENT)
        .unwrap();
    assert_eq!(
        world
            .coordinator
            .release_resource_on_exit(&of, &backend.processes, &[&stray]),
        Err(exit_refused(ExitRefusal::NotTheBoundProcess {
            identity: stray.identity()
        }))
    );
    // A runner of the execution holds no memory here: its proof is of another role.
    let role = runner(&of, super::generations(1, 1));
    let (runners, runner_proof) = bound_elsewhere(role.clone());
    assert_eq!(
        world
            .coordinator
            .release_resource_on_exit(&of, &runners, &[&runner_proof]),
        Err(exit_refused(ExitRefusal::OtherRole { role }))
    );
    assert!(!returned(&world, &of));

    let vm_proof = backend
        .processes
        .process(&vm)
        .unwrap()
        .terminate(kill_now())
        .unwrap();
    assert!(world
        .coordinator
        .release_resource_on_exit(&of, &backend.processes, &[&vm_proof])
        .is_ok());
    assert!(returned(&world, &of));
    // Released once; a second release is out of order.
    assert!(matches!(
        world
            .coordinator
            .release_resource_on_exit(&of, &backend.processes, &[&vm_proof]),
        Err(ReturnRefusal::OutOfOrder {
            stage: ReturnStage::Released,
            ..
        })
    ));
}

#[test]
fn an_exclusive_gpu_never_returns_by_process_exit_and_refusals_read_back() {
    let mut world = World::new();
    let of = execution("exe-exit-exclusive");
    let mut backend = HelperVms::new(&["sleep"]);
    world.launched(&of, &mut backend);
    world.coordinator.start_running(&of).unwrap();
    assert_eq!(
        world.coordinator.begin_resource_return(
            &of,
            GpuAssignment::ExclusiveToVm,
            BTreeSet::from([CancellationBoundary::BetweenRequests]),
            BTreeSet::from([ResourceKind::GpuMemoryBytes { device: device() }]),
        ),
        Ok(ReturnStage::WorkStopped)
    );
    assert_eq!(
        world
            .coordinator
            .release_resource_on_exit(&of, &backend.processes, &[]),
        Err(ReturnRefusal::MechanismNotForAssignment {
            assignment: GpuAssignment::ExclusiveToVm,
            mechanism: ReleaseMechanism::ProcessExit,
        })
    );

    for refusal in [
        ExitRefusal::ProofRequired,
        ExitRefusal::OtherRole {
            role: vm_role("exe-exit-exclusive"),
        },
        ExitRefusal::RunnerNotProven {
            model: model(),
            generations: super::generations(2, 3),
        },
        ExitRefusal::VmNotProven {
            vm: None,
            boot: SandboxBootGeneration::FIRST,
        },
    ] {
        let wrapped = ReturnRefusal::ProcessExit { refusal };
        let json = serde_json::to_string(&wrapped).unwrap();
        assert_eq!(
            serde_json::from_str::<ReturnRefusal>(&json).unwrap(),
            wrapped
        );
        assert!(!wrapped.to_string().is_empty());
    }
}
