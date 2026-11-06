//! The VM host processes of a boot hold its teardown until the host shows each ended (VM
//! part §6.4, §6.5; VM-CP-19; S04 and M13 process side).
//!
//! The evidence port is faked where only the host's PID observation matters; the Windows
//! tests start real processes through `foundation::process` (this test executable, set to
//! sleep or exit at once, inside its own kill-on-close job) and tear down with the host's
//! own evidence.

use std::collections::BTreeMap;

use super::fresh_root_tests::{boot, ephemeral_layout, id, launch, Launched, MemoryStore};
use super::*;
use crate::foundation::coordination::{ModelGenerations, ModelId, VmInstanceId};
use crate::foundation::ids::{
    ExecutionId, GpuAllocationGeneration, ModelActivationGeneration, SandboxBootGeneration,
};
use crate::foundation::process::{
    IdentityCheck, ProcessError, ProcessIdentity, ProcessRole, TerminationProof,
};

/// Host evidence with no proofs, where the PID of each process reads as `checks` says
/// (still the same process when unlisted).
#[derive(Default)]
struct PidChecks {
    checks: BTreeMap<u32, Result<IdentityCheck, ProcessError>>,
}

impl PidChecks {
    fn of(pid: u32, check: Result<IdentityCheck, ProcessError>) -> Self {
        Self {
            checks: BTreeMap::from([(pid, check)]),
        }
    }
}

impl VmProcessEnds for PidChecks {
    fn proof(&self, _: &VmInstanceId) -> Option<&TerminationProof> {
        None
    }

    fn check(&self, identity: &ProcessIdentity) -> Result<IdentityCheck, ProcessError> {
        self.checks
            .get(&identity.pid)
            .cloned()
            .unwrap_or(Ok(IdentityCheck::Same))
    }
}

fn vm(name: &str) -> VmInstanceId {
    VmInstanceId::new(id(name))
}

/// The host process role of `vm` in boot 1 of the launched sandbox.
fn vm_role(vm: VmInstanceId) -> ProcessRole {
    let boot = boot(1);
    ProcessRole::VmHost {
        execution: boot.execution,
        vm,
        boot: boot.boot,
    }
}

/// A process as if the host had read it from a handle; the real ones come from
/// [`ManagedProcess::of`] in the Windows tests.
fn process(pid: u32, start_time_ticks: u64, role: ProcessRole) -> ManagedProcess {
    ManagedProcess {
        identity: ProcessIdentity {
            pid,
            start_time_ticks,
        },
        role,
        handle: ProcessHandleKind::HOST,
        image: id("vmm"),
    }
}

/// Whether the sandbox root and every layout entry are still on disk.
fn all_on_disk(launched: &Launched) -> bool {
    launched.root.is_dir()
        && launched
            .journal
            .entries()
            .iter()
            .all(|entry| launched.root.join(entry.name.as_str()).exists())
}

fn recorded(launched: &mut Launched, process: ManagedProcess) -> ObjectHandle {
    launched
        .journal
        .record_vm_process(&mut launched.registry, &mut launched.store, process)
        .unwrap()
}

fn tear_down(
    launched: &mut Launched,
    ends: &dyn VmProcessEnds,
) -> Result<TeardownReport, TeardownError> {
    teardown(
        &launched.parent,
        &launched.registry,
        &mut launched.journal,
        &mut launched.store,
        ends,
    )
}

#[test]
fn a_vm_process_whose_pid_still_names_it_holds_teardown_with_nothing_deleted() {
    let mut launched = launch(&ephemeral_layout());
    let running = process(4242, 1_000, vm_role(vm("vm-1")));
    recorded(&mut launched, running.clone());
    let persisted = launched.store.read_back();
    match tear_down(&mut launched, &PidChecks::default()) {
        Err(TeardownError::VmProcess { identity, refusal }) => {
            assert_eq!(identity, running.identity);
            assert_eq!(refusal, VmProcessRefusal::Running);
        }
        other => panic!("{other:?}"),
    }
    assert!(all_on_disk(&launched));
    assert_eq!(launched.journal, persisted);
    assert_eq!(launched.store.read_back(), persisted);
    assert_eq!(launched.journal.phase(), &RootPhase::Committed);
}

#[test]
fn a_pid_that_names_no_process_or_another_counts_as_ended_and_teardown_finishes() {
    for check in [IdentityCheck::Gone, IdentityCheck::Reused] {
        let mut launched = launch(&ephemeral_layout());
        let ended = process(4242, 1_000, vm_role(vm("vm-1")));
        recorded(&mut launched, ended.clone());
        let report = tear_down(&mut launched, &PidChecks::of(4242, Ok(check))).unwrap();
        assert_eq!(
            report.vm_processes,
            [EndedVmProcess {
                vm: vm("vm-1"),
                identity: ended.identity,
                evidence: ProcessEndEvidence::NoLongerHeld { check },
            }]
        );
        assert!(report.torn_down);
        assert!(!launched.root.exists());
    }
}

#[test]
fn every_vm_process_of_the_boot_must_have_ended() {
    let mut launched = launch(&ephemeral_layout());
    recorded(&mut launched, process(10, 1, vm_role(vm("vm-1"))));
    recorded(&mut launched, process(20, 2, vm_role(vm("vm-2"))));
    let first_only = PidChecks::of(10, Ok(IdentityCheck::Gone));
    match tear_down(&mut launched, &first_only) {
        Err(TeardownError::VmProcess { identity, refusal }) => {
            assert_eq!(identity.pid, 20);
            assert_eq!(refusal, VmProcessRefusal::Running);
        }
        other => panic!("{other:?}"),
    }
    assert!(all_on_disk(&launched));
    let both = PidChecks {
        checks: BTreeMap::from([
            (10, Ok(IdentityCheck::Gone)),
            (20, Ok(IdentityCheck::Reused)),
        ]),
    };
    let report = tear_down(&mut launched, &both).unwrap();
    assert_eq!(report.vm_processes.len(), 2);
    assert!(report.torn_down);
}

#[test]
fn a_process_the_host_cannot_observe_holds_teardown() {
    let mut launched = launch(&ephemeral_layout());
    recorded(&mut launched, process(4242, 1_000, vm_role(vm("vm-1"))));
    let unsupported = ProcessError::Unsupported {
        platform: "test".to_owned(),
    };
    match tear_down(
        &mut launched,
        &PidChecks::of(4242, Err(unsupported.clone())),
    ) {
        Err(TeardownError::VmProcess { refusal, .. }) => {
            assert_eq!(
                refusal,
                VmProcessRefusal::Unobservable { error: unsupported }
            );
        }
        other => panic!("{other:?}"),
    }
    assert!(all_on_disk(&launched));
}

#[test]
fn only_a_vm_host_process_of_this_boot_is_journaled_once() {
    let mut launched = launch(&ephemeral_layout());
    let refused = |launched: &mut Launched, process: ManagedProcess| {
        launched
            .journal
            .record_vm_process(&mut launched.registry, &mut launched.store, process)
            .unwrap_err()
    };
    let runner = ProcessRole::ModelRunner {
        execution: boot(1).execution,
        model: ModelId::new(id("model")),
        generations: ModelGenerations {
            activation: ModelActivationGeneration::new(1),
            gpu_allocation: GpuAllocationGeneration::new(1),
        },
    };
    assert_eq!(
        refused(&mut launched, process(1, 1, runner)),
        VmProcessRecordError::Problem(VmProcessProblem::NotAVmHost)
    );
    let other_execution = ProcessRole::VmHost {
        execution: ExecutionId::new("another-sandbox").unwrap(),
        vm: vm("vm-1"),
        boot: SandboxBootGeneration::new(1),
    };
    assert_eq!(
        refused(&mut launched, process(1, 1, other_execution)),
        VmProcessRecordError::Problem(VmProcessProblem::OtherBoot)
    );
    let other_boot = ProcessRole::VmHost {
        execution: boot(1).execution,
        vm: vm("vm-1"),
        boot: SandboxBootGeneration::new(2),
    };
    assert_eq!(
        refused(&mut launched, process(1, 1, other_boot)),
        VmProcessRecordError::Problem(VmProcessProblem::OtherBoot)
    );
    recorded(&mut launched, process(1, 1, vm_role(vm("vm-1"))));
    assert_eq!(
        refused(&mut launched, process(1, 1, vm_role(vm("vm-2")))),
        VmProcessRecordError::Problem(VmProcessProblem::AlreadyJournaled)
    );
    assert_eq!(
        refused(&mut launched, process(2, 2, vm_role(vm("vm-1")))),
        VmProcessRecordError::Problem(VmProcessProblem::AlreadyJournaled)
    );
    assert_eq!(launched.journal.vm_processes().len(), 1);
    // Once teardown finished, no VM is started on the root.
    tear_down(&mut launched, &PidChecks::of(1, Ok(IdentityCheck::Gone))).unwrap();
    assert_eq!(
        refused(&mut launched, process(3, 3, vm_role(vm("vm-3")))),
        VmProcessRecordError::Problem(VmProcessProblem::NotLaunchable)
    );
}

#[test]
fn a_vm_process_is_journaled_durably_before_it_is_registered() {
    let mut launched = launch(&ephemeral_layout());
    let failing_store = MemoryStore::failing_from(1);
    let mut store = failing_store;
    let running = process(4242, 1_000, vm_role(vm("vm-1")));
    assert_eq!(
        launched
            .journal
            .record_vm_process(&mut launched.registry, &mut store, running.clone()),
        Err(VmProcessRecordError::Journal(RootJournalFailure))
    );
    assert!(launched.journal.vm_processes().is_empty());
    assert_eq!(
        launched.registry.validate_cleanup(
            &CleanupTarget::Process {
                identity: running.identity
            },
            &ObservedIdentities::default()
        ),
        Err(CleanupRefusal::UnknownProcess { pid: 4242 })
    );
    // Recorded through the real store, it is registered with V05 under the sandbox root.
    let handle = recorded(&mut launched, running.clone());
    assert_eq!(handle.object, running.identity.digest());
    assert_eq!(launched.store.read_back().vm_processes(), [running]);
}

#[test]
fn a_restarted_supervisor_restores_the_vm_processes_and_still_waits_for_them() {
    let mut launched = launch(&ephemeral_layout());
    let running = process(4242, 1_000, vm_role(vm("vm-1")));
    recorded(&mut launched, running.clone());
    // A restart: the journal is read back strictly and the registry rebuilt from it.
    let mut recovered = launched.store.read_back();
    let mut restored = ManagedObjects::new();
    recovered.restore_registrations(&mut restored).unwrap();
    assert_eq!(recovered.vm_processes(), std::slice::from_ref(&running));
    let root_identity = recovered.root().identity().unwrap();
    let mut observed = ObservedIdentities::default();
    observed
        .roots
        .insert(recovered.boot().managed_root(), root_identity.digest());
    observed.processes.insert(4242, running.identity);
    assert_eq!(
        restored.validate_cleanup(
            &CleanupTarget::Process {
                identity: running.identity
            },
            &observed
        ),
        Ok(CleanupPlan::Terminate {
            identity: running.identity
        })
    );
    let result = teardown(
        &launched.parent,
        &restored,
        &mut recovered,
        &mut launched.store,
        &PidChecks::default(),
    );
    assert!(matches!(
        result,
        Err(TeardownError::VmProcess {
            refusal: VmProcessRefusal::Running,
            ..
        })
    ));
    assert!(all_on_disk(&launched));
}

#[test]
fn the_journal_refuses_vm_processes_that_do_not_fit_on_reading() {
    let mut launched = launch(&ephemeral_layout());
    recorded(&mut launched, process(4242, 1_000, vm_role(vm("vm-1"))));
    let stored: serde_json::Value = serde_json::from_str(launched.store.stored_json()).unwrap();
    let read = |value: &serde_json::Value| serde_json::from_value::<RootJournal>(value.clone());
    assert!(read(&stored).is_ok());

    let mut other_boot = stored.clone();
    other_boot["vm_processes"][0]["role"]["execution"] = serde_json::json!("another-sandbox");
    assert!(read(&other_boot)
        .unwrap_err()
        .to_string()
        .contains("another execution or boot"));

    let mut twice = stored.clone();
    let first = twice["vm_processes"][0].clone();
    twice["vm_processes"].as_array_mut().unwrap().push(first);
    assert!(read(&twice)
        .unwrap_err()
        .to_string()
        .contains("journaled already"));

    let mut runner = stored.clone();
    runner["vm_processes"][0]["role"] = serde_json::to_value(ProcessRole::ModelRunner {
        execution: boot(1).execution,
        model: ModelId::new(id("model")),
        generations: ModelGenerations {
            activation: ModelActivationGeneration::new(1),
            gpu_allocation: GpuAllocationGeneration::new(1),
        },
    })
    .unwrap();
    assert!(read(&runner)
        .unwrap_err()
        .to_string()
        .contains("not the host process of a VM"));

    let mut unknown = stored.clone();
    unknown["vm_processes"][0]["pidfd"] = serde_json::json!(3);
    assert!(read(&unknown).is_err());

    let mut missing = stored;
    missing.as_object_mut().unwrap().remove("vm_processes");
    assert!(read(&missing).is_err());
}

#[test]
fn a_journal_from_before_the_commit_holds_no_vm_process() {
    let tree = super::root_tests::tree();
    let parent = GrantedRoot::open(&tree.root).unwrap();
    let mut store = MemoryStore::default();
    let interrupted = super::fresh_root::create_fresh_root_with(
        &parent,
        &boot(1),
        &ephemeral_layout(),
        &mut ManagedObjects::new(),
        &mut store,
        &mut || false,
    );
    assert!(matches!(interrupted, Err(LaunchFailure::Interrupted)));
    let mut creating: serde_json::Value = serde_json::from_str(store.stored_json()).unwrap();
    creating["vm_processes"] =
        serde_json::json!([
            serde_json::to_value(process(4242, 1_000, vm_role(vm("vm-1")))).unwrap()
        ]);
    let refused = serde_json::from_value::<RootJournal>(creating).unwrap_err();
    assert!(refused.to_string().contains("not committed"), "{refused}");
}

#[cfg(windows)]
mod host {
    //! Real processes, started through `foundation::process` as a VM backend starts its VMM.

    use std::process::{Command, Stdio};
    use std::thread;
    use std::time::{Duration, Instant};

    use super::*;
    use crate::foundation::process::{Ending, Escalation, HostProcess, VmProcesses};

    const HELPER: &str = "YOUGORI_FILES_VM_PROCESS_HELPER";

    /// Not a test of its own: the body of a helper process, run when this test executable
    /// is started with the helper variable set.
    #[test]
    fn helper_process() {
        let Ok(mode) = std::env::var(HELPER) else {
            return;
        };
        let code = match mode.as_str() {
            "sleep" => {
                thread::sleep(Duration::from_secs(60));
                0
            }
            "exit" => 0,
            _ => 99,
        };
        std::process::exit(code);
    }

    /// This test executable, set to run only [`helper_process`] in `mode`.
    fn helper_command(mode: &str) -> Command {
        let path = module_path!();
        let tests = path.split_once("::").map_or(path, |(_, rest)| rest);
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--exact",
                &format!("{tests}::helper_process"),
                "--test-threads=1",
                "--quiet",
            ])
            .env(HELPER, mode)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        command
    }

    fn escalation() -> Escalation {
        Escalation {
            grace: Duration::from_millis(100),
            kill_wait: Duration::from_secs(5),
        }
    }

    /// Starts the helper in `mode` as the host process of `vm`, held by `vms`, and journals
    /// it for the launched boot.
    fn start(
        launched: &mut Launched,
        vms: &mut VmProcesses,
        vm: VmInstanceId,
        mode: &str,
    ) -> ManagedProcess {
        let started = HostProcess::spawn(&mut helper_command(mode), vm_role(vm)).unwrap();
        let managed = ManagedProcess::of(&started, id("vmm"));
        assert_eq!(managed.identity, started.identity());
        assert_eq!(&managed.role, started.role());
        assert_eq!(managed.handle, ProcessHandleKind::WindowsJobObject);
        vms.bind(started).unwrap();
        recorded(launched, managed.clone());
        managed
    }

    /// Waits, at most ten seconds, until `done`.
    fn within_ten_seconds(mut done: impl FnMut() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while !done() {
            assert!(Instant::now() < deadline, "not observed within ten seconds");
            thread::sleep(Duration::from_millis(20));
        }
    }

    #[test]
    fn the_proof_of_the_table_that_held_the_vm_process_lets_teardown_finish() {
        let mut launched = launch(&ephemeral_layout());
        let mut vms = VmProcesses::new(escalation());
        let managed = start(&mut launched, &mut vms, vm("vm-1"), "exit");
        within_ten_seconds(|| {
            vms.refresh().contains(&vm("vm-1")) || vms.proof(&vm("vm-1")).is_some()
        });
        let report = tear_down(&mut launched, &HostVmEnds::new(&vms)).unwrap();
        assert_eq!(
            report.vm_processes,
            [EndedVmProcess {
                vm: vm("vm-1"),
                identity: managed.identity,
                evidence: ProcessEndEvidence::Proven {
                    exit_code: 0,
                    ending: Ending::Exited,
                },
            }]
        );
        assert!(report.torn_down);
        assert!(!launched.root.exists());
    }

    #[test]
    fn a_running_vm_process_holds_teardown_until_its_job_is_gone() {
        let mut launched = launch(&ephemeral_layout());
        let mut vms = VmProcesses::new(escalation());
        let managed = start(&mut launched, &mut vms, vm("vm-1"), "sleep");
        match tear_down(&mut launched, &HostVmEnds::new(&vms)) {
            Err(TeardownError::VmProcess { identity, refusal }) => {
                assert_eq!(identity, managed.identity);
                assert_eq!(refusal, VmProcessRefusal::Running);
            }
            other => panic!("{other:?}"),
        }
        assert!(all_on_disk(&launched));
        // The engine goes away with its handles: the kill-on-close job ends the process.
        drop(vms);
        within_ten_seconds(|| managed.identity.check() != Ok(IdentityCheck::Same));
        // A restarted engine holds no proof; the host sees the PID no longer names it.
        let restarted = VmProcesses::new(escalation());
        let report = tear_down(&mut launched, &HostVmEnds::new(&restarted)).unwrap();
        assert!(matches!(
            report.vm_processes[0].evidence,
            ProcessEndEvidence::NoLongerHeld {
                check: IdentityCheck::Gone | IdentityCheck::Reused
            }
        ));
        assert!(report.torn_down);
        assert!(!launched.root.exists());
    }

    #[test]
    fn a_proof_of_another_process_than_the_one_journaled_holds_teardown() {
        let mut launched = launch(&ephemeral_layout());
        let mut vms = VmProcesses::new(escalation());
        let started = HostProcess::spawn(&mut helper_command("exit"), vm_role(vm("vm-1"))).unwrap();
        let real = started.identity();
        vms.bind(started).unwrap();
        // The journal names another process for the same VM.
        let impostor = process(
            real.pid,
            real.start_time_ticks.wrapping_add(1),
            vm_role(vm("vm-1")),
        );
        recorded(&mut launched, impostor);
        within_ten_seconds(|| {
            vms.refresh().contains(&vm("vm-1")) || vms.proof(&vm("vm-1")).is_some()
        });
        match tear_down(&mut launched, &HostVmEnds::new(&vms)) {
            Err(TeardownError::VmProcess { refusal, .. }) => {
                assert_eq!(refusal, VmProcessRefusal::ProofOfAnother { proven: real });
            }
            other => panic!("{other:?}"),
        }
        assert!(all_on_disk(&launched));
    }

    #[test]
    fn the_host_observes_which_process_holds_each_registered_pid() {
        let mut launched = launch(&ephemeral_layout());
        let mut vms = VmProcesses::new(escalation());
        let managed = start(&mut launched, &mut vms, vm("vm-1"), "sleep");
        let mut observed = ObservedIdentities::default();
        observed.observe_processes(&launched.registry).unwrap();
        assert_eq!(
            observed.processes.get(&managed.identity.pid),
            Some(&managed.identity)
        );
        drop(vms);
        within_ten_seconds(|| managed.identity.check() != Ok(IdentityCheck::Same));
        observed.observe_processes(&launched.registry).unwrap();
        assert_ne!(
            observed.processes.get(&managed.identity.pid),
            Some(&managed.identity)
        );
    }
}
