//! `RunPodProvider` over a fake runpodctl port playing one RunPod account, and V12's
//! `RemoteVmAdapter` driven through it: every outcome mapping, the VM refusal, a
//! substitution shown to V12, uncertain provisioning found again by its key, the key kept
//! out of argv, `Debug` and errors, oversize output, and a labelled container run end to
//! end with cost cleanup reporting `Unavailable` (VM-W39 acceptance on RunPod's side;
//! VM-D5). Nothing here runs runpodctl or opens a socket.

use std::sync::Arc;
use std::time::Duration;

use super::command::{CommandKind, RunPodSettings, RunpodctlLimits};
use super::fakes::{
    catalog, ended, exited, request, runpod_offering, settings, FakeRunpodctl, FixedKey, GPU, KEY,
    OFFERING, REGION,
};
use super::process::RunpodctlRefusal;
use super::provider::{
    pod_instance, EndpointLookup, KeyInstallOutcome, RunPodProblem, RunPodProvider,
};
use super::secret::KeyUnavailable;
use super::values::{PodId, PodName, PodStatus, UNLISTED_OFFERING_PREFIX};
use super::ParseProblem;
use crate::foundation::coordination::RevocationMilestone;
use crate::foundation::evidence::ProviderKind;
use crate::foundation::ids::{ExecutionCategory, ManualClock, OperationId};
use crate::sandbox_contract::destinations::{
    DestinationHost, HostAddressGeneration, HostAddressState,
};
use crate::sandbox_contract::provider::{
    find_encoded, SecretValue, SharedSpendLedger, SpendLedger,
};
use crate::sandbox_contract::remote::fakes::{
    account, at, attempt, config, control_key, explicit_container, host_key, pod_execution,
    provision_effect, session_id, session_key, vm_request, HostWorld, HOUR,
};
use crate::sandbox_contract::remote::{
    vm_kinds, AdapterConfig, AdapterRefusal, AdapterState, BillingOutcome, BillingReport,
    CleanupStatus, ControlSession, Delegation, EnrollmentEvidence, EnrollmentPolicy, KnownHosts,
    LookupOutcome, OfferingKind, ProviderError, ProviderInstance, ProvisionOutcome,
    RemoteProviderPort, RemoteVmAdapter, Substitution, TerminationOutcome, UncertainCause,
};
use crate::sandbox_contract::remote_ssh::{
    KeyComment, ManagementPublicKey, PortFailure, SshTermination,
};

type Provider = RunPodProvider<FakeRunpodctl, FixedKey, Arc<ManualClock>>;

/// Scripted answers: the command kind, whether the account changes, and the output.
type Scripted = Vec<(CommandKind, bool, super::RunpodctlOutput)>;

const SETTLE: Duration = Duration::from_secs(60);

fn provider_with(clock: &Arc<ManualClock>, fake: FakeRunpodctl, key: FixedKey) -> Provider {
    RunPodProvider::new(fake, key, Arc::clone(clock), catalog(), settings())
}

fn fresh_provider() -> (Provider, Arc<ManualClock>) {
    let clock = Arc::new(ManualClock::new(at(1_000)));
    let provider = provider_with(&clock, FakeRunpodctl::new(), FixedKey::fixture());
    (provider, clock)
}

fn fake(provider: &Provider) -> &FakeRunpodctl {
    provider.port()
}

fn script(provider: &mut Provider, kind: CommandKind, apply: bool, output: super::RunpodctlOutput) {
    provider.port_mut().script(kind, apply, output);
}

fn pod_name(number: u8) -> String {
    PodName::for_attempt(&attempt(number)).as_str().to_owned()
}

fn created(outcome: ProvisionOutcome) -> ProviderInstance {
    match outcome {
        ProvisionOutcome::Created { instance } => instance,
        other => panic!("{other:?}"),
    }
}

fn id(text: &str) -> PodId {
    PodId::new(text).unwrap()
}

#[test]
fn provision_creates_one_labelled_pod_named_by_the_attempt_and_reports_what_was_delivered() {
    let (mut provider, _) = fresh_provider();
    let instance = created(provider.provision(&request(attempt(1))));
    let pod = fake(&provider).pods[0].clone();
    assert_eq!(pod.name, pod_name(1));
    assert_eq!(
        instance,
        ProviderInstance {
            provider: ProviderKind::RunPod,
            region: super::fakes::region(REGION),
            offering: super::fakes::offering_name(OFFERING),
            kind: OfferingKind::ProviderContainer,
            instance: pod_instance(&id(&pod.id)),
        }
    );
    assert_eq!(
        fake(&provider).kinds(),
        [CommandKind::CreatePod, CommandKind::GetPod]
    );
    let calls = &fake(&provider).calls;
    assert_eq!(calls[0].limits, RunpodctlLimits::CREATE);
    assert_eq!(calls[1].limits, RunpodctlLimits::QUERY);
    assert_eq!(
        &calls[0].arguments[..4],
        ["pod", "create", "--name", pod_name(1).as_str()]
    );
    assert_eq!(
        calls[1].arguments,
        ["pod", "get", pod.id.as_str(), "--output", "json"]
    );
    assert_eq!(provider.last_problem(), None);
    // The pod is what was delivered: its id digests to the instance V12 holds.
    assert_ne!(instance.instance, attempt(1).digest().to_owned());
}

#[test]
fn a_vm_request_is_refused_before_anything_is_sent() {
    let (mut provider, _) = fresh_provider();
    for kind in vm_kinds() {
        let mut vm = request(attempt(1));
        vm.kind = kind;
        assert_eq!(
            provider.provision(&vm),
            ProvisionOutcome::NotCreated {
                error: ProviderError::InvalidRequest
            }
        );
        assert_eq!(
            provider.last_problem(),
            Some(&RunPodProblem::VmKindRefused { kind })
        );
    }
    let mut foreign = request(attempt(1));
    foreign.provider = ProviderKind::Crusoe;
    assert!(matches!(
        provider.provision(&foreign),
        ProvisionOutcome::NotCreated {
            error: ProviderError::InvalidRequest
        }
    ));
    assert_eq!(
        provider.last_problem(),
        Some(&RunPodProblem::ForeignProvider {
            provider: ProviderKind::Crusoe
        })
    );
    let mut unknown = request(attempt(1));
    unknown.offering = super::fakes::offering_name("pod-b200");
    assert!(matches!(
        provider.provision(&unknown),
        ProvisionOutcome::NotCreated { .. }
    ));
    assert!(fake(&provider).calls.is_empty());

    // Through V12: a VM offering claimed on RunPod fails, returns its spend and starts
    // nothing.
    let world = HostWorld::new(4 * HOUR);
    let mut offering = runpod_offering();
    offering.kind = OfferingKind::DedicatedVm;
    let ledger = ledger();
    let mut adapter = RemoteVmAdapter::plan(
        Arc::clone(&world.clock),
        attempt(2),
        crate::sandbox_contract::remote::fakes::parent(),
        &vm_request(),
        &[offering],
        config(),
    )
    .unwrap();
    adapter
        .reserve_spend(&ledger, &provision_effect(account(), 10_000_000, 2))
        .unwrap();
    let mut provider = provider_with(&world.clock, FakeRunpodctl::new(), FixedKey::fixture());
    assert_eq!(
        adapter.provision(&mut provider, &ledger),
        Err(AdapterRefusal::ProvisionFailed {
            error: ProviderError::InvalidRequest
        })
    );
    assert_eq!(
        adapter.state(),
        &AdapterState::Failed {
            error: ProviderError::InvalidRequest
        }
    );
    assert!(fake(&provider).calls.is_empty());
    let spend = *ledger.snapshot().unwrap().account(&account()).unwrap();
    assert_eq!((spend.unknown_microunits, spend.spent_microunits), (0, 0));
}

#[test]
fn provision_is_not_created_only_when_nothing_was_sent_or_the_provider_refused() {
    let clock = Arc::new(ManualClock::new(at(1_000)));
    // No key, or a value that cannot be one: nothing is started.
    for (key, reason) in [
        (None, KeyUnavailable::NotConfigured),
        (Some("has a space"), KeyUnavailable::Malformed),
        (Some(""), KeyUnavailable::Malformed),
    ] {
        let mut provider = provider_with(&clock, FakeRunpodctl::new(), FixedKey(key));
        assert_eq!(
            provider.provision(&request(attempt(1))),
            ProvisionOutcome::NotCreated {
                error: ProviderError::Unauthorized
            }
        );
        assert_eq!(
            provider.last_problem(),
            Some(&RunPodProblem::Key { reason })
        );
        assert!(fake(&provider).calls.is_empty());
    }
    let capacity = concat!(
        r#"{"error":"There are no longer any instances available with the requested "#,
        r#"specifications. Please refresh and try again."}"#
    );
    let cases = [
        (
            ended(SshTermination::NotStarted),
            ProviderError::ProviderUnavailable,
            RunPodProblem::NotStarted {
                command: CommandKind::CreatePod,
            },
        ),
        (
            exited(
                1,
                "",
                "Error: unknown flag: --ports\nUsage:\n  runpodctl pod create [flags]\n",
            ),
            ProviderError::InvalidRequest,
            RunPodProblem::ArgumentsRefused {
                command: CommandKind::CreatePod,
            },
        ),
        (
            exited(1, capacity, ""),
            ProviderError::CapacityUnavailable,
            RunPodProblem::Refused {
                command: CommandKind::CreatePod,
                error: ProviderError::CapacityUnavailable,
            },
        ),
        (
            exited(1, "", "Error: Unauthorized\n"),
            ProviderError::Unauthorized,
            RunPodProblem::Refused {
                command: CommandKind::CreatePod,
                error: ProviderError::Unauthorized,
            },
        ),
    ];
    for (output, error, problem) in cases {
        let (mut provider, _) = fresh_provider();
        script(&mut provider, CommandKind::CreatePod, false, output);
        assert_eq!(
            provider.provision(&request(attempt(1))),
            ProvisionOutcome::NotCreated { error }
        );
        assert_eq!(provider.last_problem(), Some(&problem));
        assert!(fake(&provider).pods.is_empty());
    }
}

#[test]
fn provision_is_unknown_for_a_timeout_garbled_output_or_a_failure_after_sending() {
    let detail_without_machine = format!(
        concat!(
            r#"{{"id":"fakepod0001","name":"{}","desiredStatus":"RUNNING","#,
            r#""gpuTypeId":"NVIDIA A40","gpuCount":1}}"#
        ),
        pod_name(1)
    );
    let detail_unknown_status = format!(
        r#"{{"id":"fakepod0001","name":"{}","desiredStatus":"MIGRATING"}}"#,
        pod_name(1)
    );
    let ambiguous = UncertainCause::AmbiguousResponse;
    let create = |output| vec![(CommandKind::CreatePod, true, output)];
    let after_create = |output| vec![(CommandKind::GetPod, false, output)];
    let unreadable = |command, problem| RunPodProblem::Unreadable { command, problem };
    let failed = |code| RunPodProblem::Failed {
        command: CommandKind::CreatePod,
        code,
    };
    let near_miss = concat!(
        "There are no longer any instances available with the requested ",
        "specifications; one was reserved",
    );
    let read_failed = SshTermination::PortFailed {
        failure: PortFailure::ReadFailed,
    };
    let cases: Vec<(Scripted, UncertainCause, RunPodProblem)> = vec![
        (
            create(ended(SshTermination::DeadlineReached)),
            UncertainCause::Timeout,
            RunPodProblem::DeadlineReached {
                command: CommandKind::CreatePod,
            },
        ),
        (
            create(exited(0, "Pod fakepod0001 created", "")),
            ambiguous,
            unreadable(CommandKind::CreatePod, ParseProblem::NotJson),
        ),
        (
            create(exited(0, r#"{"pod":{}}"#, "")),
            ambiguous,
            unreadable(
                CommandKind::CreatePod,
                ParseProblem::Missing { field: "id" },
            ),
        ),
        (
            create(exited(0, r#"{"error":"internal server error"}"#, "")),
            ambiguous,
            failed(None),
        ),
        (
            create(exited(1, "", "Error: something unexpected happened\n")),
            ambiguous,
            failed(Some(1)),
        ),
        (create(exited(1, "", near_miss)), ambiguous, failed(Some(1))),
        (
            create(ended(read_failed)),
            ambiguous,
            RunPodProblem::PortFailed {
                command: CommandKind::CreatePod,
                failure: PortFailure::ReadFailed,
            },
        ),
        (
            create(ended(SshTermination::NoExitStatus)),
            UncertainCause::ConnectionLost,
            RunPodProblem::NoExitStatus {
                command: CommandKind::CreatePod,
            },
        ),
        (
            after_create(ended(SshTermination::DeadlineReached)),
            UncertainCause::Timeout,
            RunPodProblem::DeadlineReached {
                command: CommandKind::GetPod,
            },
        ),
        (
            after_create(exited(0, &detail_without_machine, "")),
            ambiguous,
            unreadable(
                CommandKind::GetPod,
                ParseProblem::Missing { field: "machine" },
            ),
        ),
        (
            after_create(exited(0, &detail_unknown_status, "")),
            ambiguous,
            unreadable(CommandKind::GetPod, ParseProblem::UnknownStatus),
        ),
    ];
    for (scripts, cause, problem) in cases {
        let (mut provider, _) = fresh_provider();
        for (kind, apply, output) in scripts {
            script(&mut provider, kind, apply, output);
        }
        assert_eq!(
            provider.provision(&request(attempt(1))),
            ProvisionOutcome::Unknown { cause },
            "{problem:?}"
        );
        assert_eq!(provider.last_problem(), Some(&problem));
        // In every case a pod may exist, and it does.
        assert_eq!(fake(&provider).pods.len(), 1);
    }
}

#[test]
fn an_unknown_provision_is_found_again_by_its_key() {
    let (mut provider, _) = fresh_provider();
    script(
        &mut provider,
        CommandKind::CreatePod,
        true,
        ended(SshTermination::DeadlineReached),
    );
    assert_eq!(
        provider.provision(&request(attempt(1))),
        ProvisionOutcome::Unknown {
            cause: UncertainCause::Timeout
        }
    );
    let pod = fake(&provider).pods[0].id.clone();
    let LookupOutcome::Found { instance } = provider.find(&request(attempt(1))) else {
        panic!("{:?}", provider.last_problem());
    };
    assert_eq!(instance.instance, pod_instance(&id(&pod)));
    assert_eq!(instance.offering.as_str(), OFFERING);
    // Another attempt's key finds nothing, which is not believed this soon.
    assert!(matches!(
        provider.find(&request(attempt(2))),
        LookupOutcome::Unknown { .. }
    ));

    // Through V12: the uncertain provisioning holds its spend, cleanup finds the pod by
    // its key, removes it and confirms.
    let world = HostWorld::new(4 * HOUR);
    let ledger = ledger();
    let mut adapter = container_adapter(&world, attempt(3));
    adapter
        .reserve_spend(&ledger, &provision_effect(account(), 10_000_000, 3))
        .unwrap();
    let mut provider = provider_with(&world.clock, FakeRunpodctl::new(), FixedKey::fixture());
    script(
        &mut provider,
        CommandKind::CreatePod,
        true,
        ended(SshTermination::DeadlineReached),
    );
    assert_eq!(
        adapter.provision(&mut provider, &ledger),
        Err(AdapterRefusal::ProvisionUncertain {
            cause: UncertainCause::Timeout
        })
    );
    assert_eq!(adapter.state(), &AdapterState::Terminating);
    assert_eq!(
        adapter.terminate_step(&mut provider),
        Ok(CleanupStatus::Confirmed { attempts: 1 })
    );
    let pod = fake(&provider).pods[0].clone();
    assert_eq!(pod.status, "TERMINATED");
    assert_eq!(
        adapter.instance().map(|instance| instance.instance),
        Some(pod_instance(&id(&pod.id)))
    );
    assert_eq!(
        fake(&provider).kinds(),
        [
            CommandKind::CreatePod,
            CommandKind::ListPods,
            CommandKind::GetPod,
            CommandKind::DeletePod,
            CommandKind::ListPods
        ]
    );
    assert_eq!(
        adapter.settle_billing(&mut provider, &ledger, &mut world.delegation()),
        Ok(BillingOutcome::Uncertain {
            held_microunits: RESERVED
        })
    );
}

#[test]
fn find_maps_each_listing_to_one_conservative_outcome() {
    // Exactly one existing pod carrying the key, however RunPod stored the name.
    let (mut provider, _) = fresh_provider();
    let pod = provider
        .port_mut()
        .add_pod(&format!(" {} ", pod_name(1).to_ascii_uppercase()), "EXITED");
    provider.port_mut().add_pod(&pod_name(1), "TERMINATED");
    provider
        .port_mut()
        .add_pod("someone-elses-pod", "MIGRATING");
    // The get answers with the name as stored, so it is compared the same way.
    let LookupOutcome::Found { instance } = provider.find(&request(attempt(1))) else {
        panic!("{:?}", provider.last_problem());
    };
    assert_eq!(instance.instance, pod_instance(&id(&pod)));
    assert_eq!(
        fake(&provider).kinds(),
        [CommandKind::ListPods, CommandKind::GetPod]
    );

    // None: believed only from a listing taken after the settle window.
    let (mut provider, clock) = fresh_provider();
    provider.port_mut().add_pod(&pod_name(1), "TERMINATED");
    assert_eq!(
        provider.find(&request(attempt(1))),
        LookupOutcome::Unknown {
            cause: UncertainCause::AmbiguousResponse
        }
    );
    assert_eq!(
        provider.last_problem(),
        Some(&RunPodProblem::ListingNotSettled)
    );
    clock.advance(SETTLE);
    assert_eq!(
        provider.find(&request(attempt(1))),
        LookupOutcome::ConfirmedAbsent
    );
    assert_eq!(provider.last_problem(), None);
    // A create sent for the attempt restarts the window.
    script(
        &mut provider,
        CommandKind::CreatePod,
        false,
        exited(1, "", "Error: Unauthorized\n"),
    );
    assert!(matches!(
        provider.provision(&request(attempt(1))),
        ProvisionOutcome::NotCreated { .. }
    ));
    clock.advance(SETTLE - Duration::from_secs(1));
    assert!(matches!(
        provider.find(&request(attempt(1))),
        LookupOutcome::Unknown { .. }
    ));
    clock.advance(Duration::from_secs(1));
    assert_eq!(
        provider.find(&request(attempt(1))),
        LookupOutcome::ConfirmedAbsent
    );

    // Several, an unknown status on a matching pod, or a failed or unreadable listing.
    let several = |provider: &mut Provider| {
        provider.port_mut().add_pod(&pod_name(1), "RUNNING");
        provider.port_mut().add_pod(&pod_name(1), "EXITED");
    };
    let unknown_status = |provider: &mut Provider| {
        provider.port_mut().add_pod(&pod_name(1), "MIGRATING");
    };
    type Setup = Box<dyn Fn(&mut Provider)>;
    let cases: Vec<(Setup, UncertainCause, RunPodProblem)> = vec![
        (
            Box::new(several),
            UncertainCause::AmbiguousResponse,
            RunPodProblem::SeveralPods { count: 2 },
        ),
        (
            Box::new(unknown_status),
            UncertainCause::AmbiguousResponse,
            RunPodProblem::Unreadable {
                command: CommandKind::ListPods,
                problem: ParseProblem::UnknownStatus,
            },
        ),
        (
            Box::new(|provider: &mut Provider| {
                script(
                    provider,
                    CommandKind::ListPods,
                    false,
                    ended(SshTermination::DeadlineReached),
                )
            }),
            UncertainCause::Timeout,
            RunPodProblem::DeadlineReached {
                command: CommandKind::ListPods,
            },
        ),
        (
            Box::new(|provider: &mut Provider| {
                script(
                    provider,
                    CommandKind::ListPods,
                    false,
                    exited(0, "No pods found", ""),
                )
            }),
            UncertainCause::AmbiguousResponse,
            RunPodProblem::Unreadable {
                command: CommandKind::ListPods,
                problem: ParseProblem::NotJson,
            },
        ),
        (
            Box::new(|provider: &mut Provider| {
                script(
                    provider,
                    CommandKind::ListPods,
                    false,
                    exited(0, r#"{"pods":[]}"#, ""),
                )
            }),
            UncertainCause::AmbiguousResponse,
            RunPodProblem::Unreadable {
                command: CommandKind::ListPods,
                problem: ParseProblem::NotAList,
            },
        ),
        (
            Box::new(|provider: &mut Provider| {
                script(
                    provider,
                    CommandKind::ListPods,
                    false,
                    exited(0, r#"[{"name":"x","desiredStatus":"RUNNING"}]"#, ""),
                )
            }),
            UncertainCause::AmbiguousResponse,
            RunPodProblem::Unreadable {
                command: CommandKind::ListPods,
                problem: ParseProblem::Missing { field: "id" },
            },
        ),
        (
            Box::new(|provider: &mut Provider| {
                script(
                    provider,
                    CommandKind::ListPods,
                    false,
                    exited(1, "", "Error: Unauthorized"),
                )
            }),
            UncertainCause::ConnectionLost,
            RunPodProblem::Refused {
                command: CommandKind::ListPods,
                error: ProviderError::Unauthorized,
            },
        ),
    ];
    for (setup, cause, problem) in cases {
        let (mut provider, clock) = fresh_provider();
        clock.advance(SETTLE);
        setup(&mut provider);
        assert_eq!(
            provider.find(&request(attempt(1))),
            LookupOutcome::Unknown { cause },
            "{problem:?}"
        );
        assert_eq!(provider.last_problem(), Some(&problem));
    }
    // No key: nothing is asked, and nothing is confirmed.
    let clock = Arc::new(ManualClock::new(at(1_000)));
    let mut provider = provider_with(&clock, FakeRunpodctl::new(), FixedKey(None));
    clock.advance(SETTLE);
    assert_eq!(
        provider.find(&request(attempt(1))),
        LookupOutcome::Unknown {
            cause: UncertainCause::ConnectionLost
        }
    );
}

#[test]
fn terminate_is_confirmed_only_when_a_follow_up_listing_no_longer_shows_the_pod() {
    let (mut provider, _) = fresh_provider();
    let instance = created(provider.provision(&request(attempt(1))));
    assert_eq!(provider.terminate(&instance), TerminationOutcome::Confirmed);
    assert_eq!(fake(&provider).pods[0].status, "TERMINATED");
    assert_eq!(
        fake(&provider).kinds()[2..],
        [CommandKind::DeletePod, CommandKind::ListPods]
    );
    assert_eq!(fake(&provider).calls[2].limits, RunpodctlLimits::CHANGE);
    // Again: the delete fails, and the listing shows the pod gone.
    assert_eq!(
        provider.terminate(&instance),
        TerminationOutcome::AlreadyGone
    );

    // The delete is answered, but the pod is still listed: not confirmed.
    let (mut provider, _) = fresh_provider();
    let instance = created(provider.provision(&request(attempt(1))));
    script(
        &mut provider,
        CommandKind::DeletePod,
        false,
        exited(0, "{}", ""),
    );
    assert_eq!(
        provider.terminate(&instance),
        TerminationOutcome::Unknown {
            cause: UncertainCause::AmbiguousResponse
        }
    );
    assert_eq!(
        provider.last_problem(),
        Some(&RunPodProblem::StillListed {
            status: PodStatus::Running
        })
    );
    // The follow-up listing fails: not confirmed.
    script(
        &mut provider,
        CommandKind::ListPods,
        false,
        ended(SshTermination::DeadlineReached),
    );
    assert_eq!(
        provider.terminate(&instance),
        TerminationOutcome::Unknown {
            cause: UncertainCause::Timeout
        }
    );
    assert_eq!(fake(&provider).pods[0].status, "TERMINATED");

    // A refused delete of a pod still listed fails; an unrecognised failure is unknown; a
    // timed-out delete whose pod is gone is already gone.
    let cases = [
        (
            exited(1, "", "Error: Unauthorized"),
            false,
            TerminationOutcome::Failed {
                error: ProviderError::Unauthorized,
            },
        ),
        (
            exited(1, "", "Error: pod is locked"),
            false,
            TerminationOutcome::Unknown {
                cause: UncertainCause::AmbiguousResponse,
            },
        ),
        (
            ended(SshTermination::DeadlineReached),
            false,
            TerminationOutcome::Unknown {
                cause: UncertainCause::Timeout,
            },
        ),
        (
            ended(SshTermination::DeadlineReached),
            true,
            TerminationOutcome::AlreadyGone,
        ),
        (
            ended(SshTermination::NotStarted),
            false,
            TerminationOutcome::Failed {
                error: ProviderError::ProviderUnavailable,
            },
        ),
    ];
    for (output, apply, expected) in cases {
        let (mut provider, _) = fresh_provider();
        let instance = created(provider.provision(&request(attempt(1))));
        script(&mut provider, CommandKind::DeletePod, apply, output);
        assert_eq!(provider.terminate(&instance), expected);
    }

    // A transport that never saw the pod finds it by its digest in a listing.
    let clock = Arc::new(ManualClock::new(at(1_000)));
    let mut first = provider_with(&clock, FakeRunpodctl::new(), FixedKey::fixture());
    let instance = created(first.provision(&request(attempt(1))));
    let mut account = std::mem::take(first.port_mut());
    account.calls.clear();
    let mut restarted = provider_with(&clock, account, FixedKey::fixture());
    assert_eq!(
        restarted.terminate(&instance),
        TerminationOutcome::Confirmed
    );
    assert_eq!(
        fake(&restarted).kinds(),
        [
            CommandKind::ListPods,
            CommandKind::DeletePod,
            CommandKind::ListPods
        ]
    );
    // An instance no listing holds is gone only after the settle window.
    let mut other = instance.clone();
    other.instance = pod_instance(&id("neverlisted"));
    let mut fresh = provider_with(&clock, FakeRunpodctl::new(), FixedKey::fixture());
    assert!(matches!(
        fresh.terminate(&other),
        TerminationOutcome::Unknown { .. }
    ));
    clock.advance(SETTLE);
    assert_eq!(fresh.terminate(&other), TerminationOutcome::AlreadyGone);
    // Nothing is sent without a key or for another provider's instance.
    let mut keyless = provider_with(&clock, FakeRunpodctl::new(), FixedKey(None));
    assert_eq!(
        keyless.terminate(&instance),
        TerminationOutcome::Unknown {
            cause: UncertainCause::ConnectionLost
        }
    );
    let mut foreign = instance.clone();
    foreign.provider = ProviderKind::Vast;
    assert_eq!(
        fresh.terminate(&foreign),
        TerminationOutcome::Failed {
            error: ProviderError::InvalidRequest
        }
    );
    assert!(fake(&keyless).calls.is_empty());
}

#[test]
fn final_bill_is_unavailable_and_calls_nothing() {
    let (mut provider, _) = fresh_provider();
    let instance = created(provider.provision(&request(attempt(1))));
    provider.terminate(&instance);
    let calls = fake(&provider).calls.len();
    assert_eq!(provider.final_bill(&attempt(1)), BillingReport::Unavailable);
    assert_eq!(fake(&provider).calls.len(), calls);
    assert_eq!(provider.last_problem(), None);
}

#[test]
fn a_delivered_region_other_than_the_request_is_a_substitution_to_v12() {
    let world = HostWorld::new(4 * HOUR);
    let ledger = ledger();
    let mut adapter = container_adapter(&world, attempt(1));
    adapter
        .reserve_spend(&ledger, &provision_effect(account(), 10_000_000, 1))
        .unwrap();
    let mut fake = FakeRunpodctl::new();
    fake.deliver_region = Some("US-KS-2".to_owned());
    let mut provider = provider_with(&world.clock, fake, FixedKey::fixture());
    assert_eq!(
        adapter.provision(&mut provider, &ledger),
        Err(AdapterRefusal::Substituted {
            substitution: Substitution::Region {
                requested: super::fakes::region(REGION),
                delivered: super::fakes::region("US-KS-2"),
            }
        })
    );
    assert_eq!(adapter.state(), &AdapterState::Terminating);
    assert_eq!(
        adapter.terminate_step(&mut provider),
        Ok(CleanupStatus::Confirmed { attempts: 1 })
    );
    assert_eq!(provider.port().pods[0].status, "TERMINATED");

    // Another GPU shows as another offering: the configured one, or an unlisted name.
    for (gpu, offering) in [
        ("NVIDIA H100 80GB HBM3", Some("pod-h100")),
        ("NVIDIA L4", None),
    ] {
        let (mut provider, _) = fresh_provider();
        provider.port_mut().deliver_gpu = Some((gpu.to_owned(), 1));
        let instance = created(provider.provision(&request(attempt(1))));
        match offering {
            Some(name) => assert_eq!(instance.offering.as_str(), name),
            None => assert!(instance
                .offering
                .as_str()
                .starts_with(UNLISTED_OFFERING_PREFIX)),
        }
    }
    let (mut provider, _) = fresh_provider();
    provider.port_mut().deliver_gpu = Some((GPU.to_owned(), 2));
    let instance = created(provider.provision(&request(attempt(1))));
    assert_ne!(instance.offering.as_str(), OFFERING);
}

#[test]
fn the_api_key_never_appears_in_argv_debug_or_any_error() {
    let (mut provider, clock) = fresh_provider();
    let echo = format!("Error: invalid key {KEY}\n");
    let management = management_key();
    let host = HostAddressState::new(HostAddressGeneration::FIRST, []);
    let mut seen = Vec::new();
    seen.push(format!(
        "{:?}",
        provider.install_management_key(&management)
    ));
    let instance = created(provider.provision(&request(attempt(1))));
    seen.push(format!("{:?}", provider.find(&request(attempt(1)))));
    seen.push(format!("{:?}", provider.ssh_endpoint(&instance, &host)));
    seen.push(format!("{:?}", provider.terminate(&instance)));
    // runpodctl echoing the key in its errors: nothing of it is kept.
    for kind in [CommandKind::CreatePod, CommandKind::ListPods] {
        script(
            &mut provider,
            kind,
            false,
            exited(1, &format!(r#"{{"error":"{echo}"}}"#), &echo),
        );
    }
    seen.push(format!("{:?}", provider.provision(&request(attempt(2)))));
    seen.push(format!("{:?}", provider.last_problem()));
    seen.push(serde_json::to_string(&provider.last_problem()).unwrap());
    clock.advance(SETTLE);
    seen.push(format!("{:?}", provider.find(&request(attempt(2)))));
    seen.push(format!("{:?}", provider.last_problem()));
    seen.push(format!("{provider:?}"));
    seen.push(format!("{:?}", SecretValue::new(KEY.as_bytes().to_vec())));
    seen.push(format!(
        "{} {:?}",
        RunpodctlRefusal::KeyNotText,
        RunpodctlRefusal::KeyNotText
    ));
    seen.push(format!(
        "{} {:?}",
        KeyUnavailable::Malformed,
        KeyUnavailable::Malformed
    ));
    let kinds: std::collections::BTreeSet<CommandKind> =
        fake(&provider).calls.iter().map(|call| call.kind).collect();
    assert_eq!(kinds.len(), 6, "every command kind ran: {kinds:?}");
    for call in &fake(&provider).calls {
        assert_eq!(call.key, KEY.as_bytes(), "the key went to the port");
        assert_eq!(
            find_encoded(call.arguments.join("\u{0}").as_bytes(), KEY.as_bytes()),
            None,
            "{:?}",
            call.kind
        );
        seen.push(format!("{:?}", call.arguments));
    }
    for text in &seen {
        assert_eq!(
            find_encoded(text.as_bytes(), KEY.as_bytes()),
            None,
            "{text}"
        );
    }
}

#[test]
fn output_over_its_bound_is_never_parsed() {
    let small = RunpodctlLimits::new(Duration::from_secs(40), 512, 512).unwrap();
    let clock = Arc::new(ManualClock::new(at(1_000)));
    let mut provider = RunPodProvider::new(
        FakeRunpodctl::new(),
        FixedKey::fixture(),
        Arc::clone(&clock),
        catalog(),
        RunPodSettings {
            query: small,
            create: small,
            ..settings()
        },
    );
    clock.advance(SETTLE);
    // A well-formed listing holding the pod, one byte over the bound: not read.
    let row = format!(
        r#"{{"id":"fakepod0001","name":"{}","desiredStatus":"RUNNING","pad":""}}"#,
        pod_name(1)
    );
    let padding = 512 + 1 - (row.len() + 2);
    let listing = format!(
        "[{}]",
        row.replace(
            r#""pad":"""#,
            &format!(r#""pad":"{}""#, "x".repeat(padding))
        )
    );
    assert_eq!(listing.len(), 513);
    script(
        &mut provider,
        CommandKind::ListPods,
        false,
        exited(0, &listing, ""),
    );
    assert_eq!(
        provider.find(&request(attempt(1))),
        LookupOutcome::Unknown {
            cause: UncertainCause::AmbiguousResponse
        }
    );
    assert_eq!(
        provider.last_problem(),
        Some(&RunPodProblem::OutputOverBound {
            command: CommandKind::ListPods,
            stream: crate::sandbox_contract::remote_ssh::OutputStream::Stdout
        })
    );
    // A created pod whose stderr passed its bound: unknown, never created.
    script(
        &mut provider,
        CommandKind::CreatePod,
        true,
        exited(0, r#"{"id":"fakepod0009"}"#, &"w".repeat(513)),
    );
    assert_eq!(
        provider.provision(&request(attempt(1))),
        ProvisionOutcome::Unknown {
            cause: UncertainCause::AmbiguousResponse
        }
    );
    assert_eq!(
        provider.last_problem(),
        Some(&RunPodProblem::OutputOverBound {
            command: CommandKind::CreatePod,
            stream: crate::sandbox_contract::remote_ssh::OutputStream::Stderr
        })
    );
}

#[test]
fn the_ssh_endpoint_is_the_public_address_runpod_reports() {
    let host = HostAddressState::new(HostAddressGeneration::FIRST, []);
    let (mut provider, _) = fresh_provider();
    let instance = created(provider.provision(&request(attempt(1))));
    let EndpointLookup::Ready { authority } = provider.ssh_endpoint(&instance, &host) else {
        panic!("{:?}", provider.last_problem());
    };
    assert_eq!(
        authority.host,
        DestinationHost::Address("194.68.245.20".parse().unwrap())
    );
    assert_eq!(authority.port.get(), 22_101);
    let set = |provider: &mut Provider, status: &str, ssh: Option<(&str, u16)>| {
        let pod = &mut provider.port_mut().pods[0];
        pod.status = status.to_owned();
        pod.ssh = ssh.map(|(ip, port)| (ip.to_owned(), port));
    };
    set(&mut provider, "RUNNING", None);
    assert_eq!(
        provider.ssh_endpoint(&instance, &host),
        EndpointLookup::NotReady {
            status: PodStatus::Running
        }
    );
    set(&mut provider, "EXITED", Some(("194.68.245.20", 22_101)));
    assert_eq!(
        provider.ssh_endpoint(&instance, &host),
        EndpointLookup::NotReady {
            status: PodStatus::Exited
        }
    );
    set(&mut provider, "RUNNING", Some(("127.0.0.1", 22)));
    assert!(matches!(
        provider.ssh_endpoint(&instance, &host),
        EndpointLookup::Refused { .. }
    ));
    set(&mut provider, "RUNNING", Some(("010.1.1.1", 22)));
    assert_eq!(
        provider.ssh_endpoint(&instance, &host),
        EndpointLookup::Unknown {
            cause: UncertainCause::AmbiguousResponse
        }
    );
    set(&mut provider, "TERMINATED", None);
    assert_eq!(
        provider.ssh_endpoint(&instance, &host),
        EndpointLookup::Gone
    );
}

fn management_key() -> ManagementPublicKey {
    use base64::Engine as _;
    let mut blob = Vec::new();
    blob.extend_from_slice(&11_u32.to_be_bytes());
    blob.extend_from_slice(b"ssh-ed25519");
    blob.extend_from_slice(&32_u32.to_be_bytes());
    blob.extend_from_slice(&[7_u8; 32]);
    let line = format!(
        "ssh-ed25519 {} yougori-mgmt\n",
        base64::engine::general_purpose::STANDARD.encode(&blob)
    );
    ManagementPublicKey::parse(line.as_bytes(), &KeyComment::new("yougori-mgmt").unwrap()).unwrap()
}

#[test]
fn the_management_key_is_put_on_the_account_once_and_checked() {
    let key = management_key();
    let (mut provider, _) = fresh_provider();
    assert_eq!(
        provider.install_management_key(&key),
        KeyInstallOutcome::Installed
    );
    assert_eq!(
        fake(&provider).kinds(),
        [
            CommandKind::ListSshKeys,
            CommandKind::AddSshKey,
            CommandKind::ListSshKeys
        ]
    );
    assert_eq!(
        fake(&provider).calls[1].arguments,
        [
            "ssh".to_owned(),
            "add-key".to_owned(),
            "--key".to_owned(),
            key.authorized_keys_line(),
            "--output".to_owned(),
            "json".to_owned()
        ]
    );
    assert_eq!(
        provider.install_management_key(&key),
        KeyInstallOutcome::AlreadyPresent
    );
    assert_eq!(fake(&provider).count(CommandKind::AddSshKey), 1);

    let (mut provider, _) = fresh_provider();
    script(
        &mut provider,
        CommandKind::AddSshKey,
        false,
        exited(1, "", "Error: Unauthorized"),
    );
    assert_eq!(
        provider.install_management_key(&key),
        KeyInstallOutcome::NotInstalled {
            error: ProviderError::Unauthorized
        }
    );
    script(
        &mut provider,
        CommandKind::AddSshKey,
        false,
        exited(0, "{}", ""),
    );
    assert_eq!(
        provider.install_management_key(&key),
        KeyInstallOutcome::Unknown {
            cause: UncertainCause::AmbiguousResponse
        }
    );
    assert_eq!(provider.last_problem(), Some(&RunPodProblem::KeyNotListed));
    script(
        &mut provider,
        CommandKind::ListSshKeys,
        false,
        exited(0, "[]", ""),
    );
    assert!(matches!(
        provider.install_management_key(&key),
        KeyInstallOutcome::Unknown { .. }
    ));
}

const BUDGET: u64 = 100_000_000;
/// The offering's 2,000,000 µ/h over the 2 h lifetime plus the 600 s termination
/// allowance: 7,800 s × 2,000,000 / 3,600 = 4,333,333.3, rounded up.
const RESERVED: u64 = 4_333_334;

fn ledger() -> SharedSpendLedger {
    let ledger = SharedSpendLedger::new(SpendLedger::new());
    ledger
        .with(|book| book.open_account(account(), BUDGET))
        .unwrap();
    ledger
}

/// RunPod reports no host key, so a pod is enrolled on first use, allowed explicitly.
fn container_config() -> AdapterConfig {
    AdapterConfig {
        enrollment: EnrollmentPolicy {
            allow_first_use: true,
        },
        ..config()
    }
}

fn container_adapter(
    world: &HostWorld<Arc<ManualClock>>,
    attempt: crate::sandbox_contract::remote::AttemptId,
) -> RemoteVmAdapter<Arc<ManualClock>> {
    RemoteVmAdapter::plan(
        Arc::clone(&world.clock),
        attempt,
        pod_execution(),
        &explicit_container(),
        &[runpod_offering()],
        container_config(),
    )
    .unwrap()
}

#[test]
fn a_labelled_runpod_container_runs_end_to_end_through_v12_and_cleanup_reports_unavailable() {
    let mut world = HostWorld::new(4 * HOUR);
    let mut authority = world.delegation();
    let ledger = ledger();
    let mut known = KnownHosts::new();
    let mut adapter = container_adapter(&world, attempt(1));
    assert_eq!(
        adapter.selection().label(),
        "remote runtime (provider container), not a sandbox"
    );
    assert_eq!(adapter.selection().decision(), Some("VM-D5"));
    let mut provider = provider_with(&world.clock, FakeRunpodctl::new(), FixedKey::fixture());

    adapter
        .reserve_spend(&ledger, &provision_effect(account(), 10_000_000, 1))
        .unwrap();
    let instance = adapter.provision(&mut provider, &ledger).unwrap();
    assert_eq!(instance.kind, OfferingKind::ProviderContainer);
    assert_eq!(instance.provider, ProviderKind::RunPod);
    adapter
        .enroll(&mut known, &host_key(1), EnrollmentEvidence::FirstUse)
        .unwrap();
    let offer = world.remote_offer(
        instance.instance,
        ExecutionCategory::ProviderContainerRuntime,
    );
    let admitted = adapter.confirm_runtime(&offer, None).unwrap();
    world
        .authorize_labelled(pod_execution(), admitted, HOUR)
        .unwrap();
    let session = ControlSession::open(
        adapter.identity().unwrap().clone(),
        session_id(1),
        session_key(1),
        control_key(1),
        world.now(),
    );
    adapter
        .connect(&known, &host_key(1), session, &mut authority)
        .unwrap();
    adapter
        .launch(&mut authority, OperationId::new("op-pod").unwrap(), None)
        .unwrap();
    assert_eq!(adapter.state(), &AdapterState::Running);
    assert!(matches!(
        adapter.delegation(),
        Some(Delegation::Labelled { .. })
    ));
    assert!(adapter.lease().is_none());

    world.advance(Duration::from_secs(30 * 60));
    adapter.begin_termination(&mut authority).unwrap();
    assert_eq!(
        adapter.terminate_step(&mut provider),
        Ok(CleanupStatus::Confirmed { attempts: 1 })
    );
    assert_eq!(provider.port().pods[0].status, "TERMINATED");
    let billing = adapter.settle_billing(&mut provider, &ledger, &mut authority);
    assert_eq!(
        billing,
        Ok(BillingOutcome::Uncertain {
            held_microunits: RESERVED
        })
    );
    assert_eq!(
        adapter.state(),
        &AdapterState::Closed {
            billing: BillingOutcome::Uncertain {
                held_microunits: RESERVED
            }
        }
    );
    let spend = *ledger.snapshot().unwrap().account(&account()).unwrap();
    assert_eq!(
        (spend.unknown_microunits, spend.spent_microunits),
        (RESERVED, 0)
    );
    // A container is not a VM, and RunPod never states that billing stopped.
    assert!(!adapter
        .acknowledgments()
        .contains_key(&RevocationMilestone::VmStopped));
    assert!(!adapter
        .acknowledgments()
        .contains_key(&RevocationMilestone::ProviderStoppedBilling));
    assert_eq!(
        provider.port().kinds(),
        [
            CommandKind::CreatePod,
            CommandKind::GetPod,
            CommandKind::DeletePod,
            CommandKind::ListPods
        ]
    );
}
