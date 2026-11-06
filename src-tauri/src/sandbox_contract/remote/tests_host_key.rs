//! M16E: a rejected host key ends delegation and holds everywhere (M16 (c4); VM-W41
//! acceptance "host-key changes rejected"; VM part §6.3, §7.6; VM-P40).
//!
//! A real [`RemoteVmAdapter`] on V12's fakes and a real CORE-04 coordinator, as in
//! `tests_lifecycle`: a changed key at connect and a mismatch management reports are
//! recorded against the enrollment in [`KnownHosts`] and end delegated authority at once;
//! every check then refuses the enrollment until the host is enrolled again under a new
//! generation; the record round-trips strictly. Nothing here opens a connection.

use std::collections::BTreeSet;
use std::sync::Arc;

use super::adapter::{
    AdapterRefusal, AdapterState, AdapterStep, AuthorityEnd, BillingOutcome, CleanupStatus,
    Delegation, RemoteVmAdapter,
};
use super::argv::{ArgvRefusal, OptionTerminator, ProgramPath, RemoteCommand, RemoteInvocation};
use super::control::{ControlSession, RemoteIdentity};
use super::fakes::{
    account, at, attempt, config, container_offering, control_key, dedicated_offering,
    explicit_container, host_id, host_key, mgmt_key, parent, pod_execution, provision_effect,
    session_id, session_key, vm_request, FakeProvider, GrantAll, HostWorld, HOUR, MINUTE, SECOND,
};
use super::lease::{CoordinatorDelegation, HostAuthority};
use super::rejection::RejectionObserver::{ControlConnect, ManagementSsh};
use super::rejection::{
    HostKeyRejection, PrintedFingerprint, RejectionEvidence, RejectionObserver, RejectionRefusal,
    MAX_PRINTED_FINGERPRINT_BYTES,
};
use super::ssh::{
    EnrollmentEvidence, EnrollmentPolicy, EnrollmentRefusal, ExecutionContext, HostEnrollment,
    HostKey, HostKeyRefusal, KnownHosts, ManagementAction, ManagementIdentity, ManagementRefusal,
    RemoteAccountName, RemoteShellKind,
};
use crate::foundation::coordination::RevocationMilestone;
use crate::foundation::ids::{ExecutionCategory, ManualClock, OperationId};
use crate::sandbox_contract::provider::{SharedSpendLedger, SpendLedger};

type HostDelegation = CoordinatorDelegation<Arc<ManualClock>, GrantAll>;

const BUDGET: u64 = 100_000_000;
const COST: u64 = 1_500_000;
/// OpenSSH's SHA256 form: `SHA256:` and 43 base64 characters.
const OPENSSH_FINGERPRINT: &str = "SHA256:uNiVztksCsDhcc0u9e8BujQXVUpKZIDTMczCvj3tD2s";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    /// A dedicated provider VM under a CORE-04 service lease.
    Vm,
    /// A provider container under its labelled-runtime record (VM-D5).
    Container,
}

struct Run {
    world: HostWorld<Arc<ManualClock>>,
    authority: HostDelegation,
    provider: FakeProvider,
    ledger: SharedSpendLedger,
    known: KnownHosts,
    adapter: RemoteVmAdapter<Arc<ManualClock>>,
}

impl Run {
    /// A run of `kind` on attempt 1, so on the same host every time, checking keys
    /// against `known`, provisioned.
    fn provisioned(kind: Kind, known: KnownHosts) -> Self {
        let world = HostWorld::new(4 * HOUR);
        let authority = world.delegation();
        let ledger = SharedSpendLedger::new(SpendLedger::new());
        ledger
            .with(|book| book.open_account(account(), BUDGET))
            .unwrap();
        let (offering, request, execution) = match kind {
            Kind::Vm => (dedicated_offering(), vm_request(), parent()),
            Kind::Container => (container_offering(), explicit_container(), pod_execution()),
        };
        let adapter = RemoteVmAdapter::plan(
            Arc::clone(&world.clock),
            attempt(1),
            execution,
            &request,
            &[offering],
            config(),
        )
        .unwrap();
        let mut run = Self {
            world,
            authority,
            provider: FakeProvider {
                default_cost_microunits: COST,
                ..FakeProvider::default()
            },
            ledger,
            known,
            adapter,
        };
        run.adapter
            .reserve_spend(&run.ledger, &provision_effect(account(), 10_000_000, 1))
            .unwrap();
        run.adapter
            .provision(&mut run.provider, &run.ledger)
            .unwrap();
        run
    }

    /// Provisioned, and the host enrolled with `key` through the provider's API.
    fn enrolled(kind: Kind, known: KnownHosts, key: &HostKey) -> Self {
        let mut run = Self::provisioned(kind, known);
        run.adapter
            .enroll(&mut run.known, key, provider_api(key))
            .unwrap();
        run
    }

    /// Enrolled, and the runtime confirmed; a container also granted its labelled record.
    fn confirmed(kind: Kind, known: KnownHosts, key: &HostKey) -> Self {
        let mut run = Self::enrolled(kind, known, key);
        let instance = run.adapter.instance().unwrap().instance;
        match kind {
            Kind::Vm => {
                let offer = run
                    .world
                    .remote_offer(instance, ExecutionCategory::VmSandbox);
                run.adapter.confirm_runtime(&offer, None).unwrap();
            }
            Kind::Container => {
                let offer = run
                    .world
                    .remote_offer(instance, ExecutionCategory::ProviderContainerRuntime);
                let admitted = run.adapter.confirm_runtime(&offer, None).unwrap();
                run.world
                    .authorize_labelled(pod_execution(), admitted, HOUR)
                    .unwrap();
            }
        }
        run
    }

    /// Confirmed with `key`, connected and launched.
    fn running_with(kind: Kind, known: KnownHosts, key: &HostKey) -> Self {
        let mut run = Self::confirmed(kind, known, key);
        run.connect(1, key).unwrap();
        run.launch().unwrap();
        assert_eq!(run.adapter.state(), &AdapterState::Running);
        run
    }

    /// Running on host key 1.
    fn running(kind: Kind) -> Self {
        Self::running_with(kind, KnownHosts::new(), &host_key(1))
    }

    // The error type is V12's own; this helper only passes it through.
    #[allow(clippy::result_large_err)]
    fn connect(&mut self, number: u8, key: &HostKey) -> Result<(), AdapterRefusal> {
        let session = ControlSession::open(
            self.identity(),
            session_id(number),
            session_key(number),
            control_key(number),
            self.world.now(),
        );
        self.adapter
            .connect(&self.known, key, session, &mut self.authority)
    }

    #[allow(clippy::result_large_err)]
    fn launch(&mut self) -> Result<(), AdapterRefusal> {
        self.adapter
            .launch(
                &mut self.authority,
                OperationId::new("op-remote").unwrap(),
                None,
            )
            .map(|_| ())
    }

    #[allow(clippy::result_large_err)]
    fn report(&mut self, evidence: RejectionEvidence) -> Result<HostKeyRejection, AdapterRefusal> {
        self.adapter
            .report_host_key_mismatch(&self.known, &mut self.authority, evidence)
    }

    fn identity(&self) -> RemoteIdentity {
        self.adapter.identity().unwrap().clone()
    }

    /// The host's current enrollment.
    fn enrollment(&self) -> HostEnrollment {
        self.known
            .enrollment(&self.identity().host)
            .unwrap()
            .clone()
    }

    /// The state a rejection of the run's enrollment, seen by `observer`, ends it in.
    fn ended_by(&self, observer: RejectionObserver) -> AdapterState {
        let identity = self.identity();
        AdapterState::AuthorityEnded {
            reason: AuthorityEnd::HostKeyRejected {
                host: identity.host,
                generation: identity.enrollment,
                observer,
            },
        }
    }

    /// Whether the host authority itself still honours the run's delegation.
    fn host_honours(&mut self) -> bool {
        match self.adapter.delegation().cloned() {
            Some(Delegation::Lease { lease }) => self.authority.check(lease.id()).is_ok(),
            Some(Delegation::Labelled { grant }) => self
                .authority
                .check_labelled(&pod_execution())
                .is_ok_and(|record| record.grant == grant),
            None => false,
        }
    }

    /// Terminates, confirmed at the first attempt, and settles billing.
    fn terminate_and_settle(&mut self) -> BillingOutcome {
        self.adapter.begin_termination(&mut self.authority).unwrap();
        assert_eq!(
            self.adapter.terminate_step(&mut self.provider),
            Ok(CleanupStatus::Confirmed { attempts: 1 })
        );
        let outcome = self
            .adapter
            .settle_billing(&mut self.provider, &self.ledger, &mut self.authority)
            .unwrap();
        assert_eq!(
            self.adapter.state(),
            &AdapterState::Closed { billing: outcome }
        );
        outcome
    }

    fn acknowledged(&self, milestone: RevocationMilestone) -> bool {
        self.adapter.acknowledgments().contains_key(&milestone)
    }
}

fn provider_api(key: &HostKey) -> EnrollmentEvidence {
    EnrollmentEvidence::ProviderApi {
        reported: key.fingerprint(),
    }
}

#[test]
fn adopting_shared_enrollment_neither_enrolls_nor_forgives_a_rejected_key() {
    let mut first = Run::provisioned(Kind::Vm, KnownHosts::new());
    let host = first.adapter.instance().unwrap().host();
    let mut book = KnownHosts::new();
    let enrollment = book
        .enroll(
            host,
            &host_key(1),
            provider_api(&host_key(1)),
            EnrollmentPolicy::default(),
            at(1),
        )
        .unwrap();
    let shared = Arc::new(book);
    let before = shared.snapshot();
    let identity = first
        .adapter
        .adopt_enrollment(&shared, &host_key(1))
        .unwrap();
    assert_eq!(identity, RemoteIdentity::from_enrollment(&enrollment));
    assert_eq!(shared.snapshot(), before);

    let other_channel = Arc::clone(&shared);
    other_channel
        .record_rejection(
            &host,
            enrollment.generation,
            ManagementSsh,
            RejectionEvidence::SshUnverified,
            at(2),
        )
        .unwrap();
    assert!(management_identity(&enrollment)
        .check_current(&shared)
        .is_err());
    let mut second = Run::provisioned(Kind::Vm, KnownHosts::new());
    assert_eq!(second.adapter.instance().unwrap().host(), host);
    assert!(matches!(
        second.adapter.adopt_enrollment(&shared, &host_key(1)),
        Err(AdapterRefusal::HostKey {
            refusal: HostKeyRefusal::Rejected { .. }
        })
    ));
    assert_eq!(second.adapter.state(), &AdapterState::Provisioned);
    assert_eq!(shared.rejections().len(), 1);
}

fn printed() -> PrintedFingerprint {
    PrintedFingerprint::new(OPENSSH_FINGERPRINT).unwrap()
}

fn management_identity(enrollment: &HostEnrollment) -> ManagementIdentity {
    ManagementIdentity::new(
        enrollment,
        RemoteAccountName::new("yougori").unwrap(),
        mgmt_key(),
        RemoteShellKind::Posix,
        BTreeSet::from([ManagementAction::CollectLogs, ManagementAction::TerminateVm]),
    )
    .unwrap()
}

const SETTLED: BillingOutcome = BillingOutcome::Settled {
    charged_microunits: COST,
};

#[test]
fn a_changed_key_at_connect_is_recorded_and_ends_authority_at_once() {
    let mut run = Run::running(Kind::Vm);
    let identity = run.identity();
    let enrollment = run.enrollment();
    assert!(run.host_honours());
    let now = run.world.now();
    assert_eq!(
        run.connect(2, &host_key(9)),
        Err(AdapterRefusal::HostKey {
            refusal: HostKeyRefusal::Changed {
                host: identity.host,
                enrolled: host_key(1).fingerprint(),
                presented: host_key(9).fingerprint(),
            }
        })
    );
    // At once: no time passed, and the host no longer honours the lease.
    assert_eq!(run.world.now(), now);
    assert_eq!(run.adapter.state(), &run.ended_by(ControlConnect));
    assert!(!run.host_honours());
    assert_eq!(
        run.adapter
            .acknowledgments()
            .get(&RevocationMilestone::NewAuthorizationsDenied),
        Some(&now)
    );
    assert_eq!(
        run.known.rejection(&identity.host, identity.enrollment),
        Some(HostKeyRejection {
            enrollment,
            observer: ControlConnect,
            evidence: RejectionEvidence::PresentedKey {
                presented: host_key(9).fingerprint(),
            },
            rejected_at: now,
        })
    );
    assert!(matches!(
        run.adapter.renew(&mut run.authority),
        Err(AdapterRefusal::InvalidStep { .. })
    ));
    // Termination and billing proceed as for any ended authority.
    assert_eq!(run.terminate_and_settle(), SETTLED);
    assert!(run.acknowledged(RevocationMilestone::VmStopped));
    assert!(run.acknowledged(RevocationMilestone::ProviderStoppedBilling));

    // Before launch there is nothing to release, and the run never launches.
    let mut run = Run::confirmed(Kind::Vm, KnownHosts::new(), &host_key(1));
    assert!(matches!(
        run.connect(1, &host_key(9)),
        Err(AdapterRefusal::HostKey {
            refusal: HostKeyRefusal::Changed { .. }
        })
    ));
    let ended = run.ended_by(ControlConnect);
    assert_eq!(run.adapter.state(), &ended);
    assert_eq!(
        run.launch(),
        Err(AdapterRefusal::InvalidStep {
            state: ended,
            step: AdapterStep::Launch
        })
    );
    assert!(run.adapter.delegation().is_none());
    assert_eq!(run.terminate_and_settle(), SETTLED);
}

#[test]
fn a_management_report_is_recorded_and_ends_authority_at_once() {
    let mut run = Run::running(Kind::Vm);
    let identity = run.identity();
    let enrollment = run.enrollment();
    let evidence = RejectionEvidence::SshKeyChanged {
        printed: Some(printed()),
    };
    let now = run.world.now();
    let rejection = run.report(evidence.clone()).unwrap();
    assert_eq!(
        rejection,
        HostKeyRejection {
            enrollment,
            observer: ManagementSsh,
            evidence,
            rejected_at: now,
        }
    );
    assert_eq!(
        run.known.rejection(&identity.host, identity.enrollment),
        Some(rejection.clone())
    );
    assert_eq!(run.adapter.state(), &run.ended_by(ManagementSsh));
    assert!(!run.host_honours());
    // A later report keeps the first record and changes nothing.
    run.world.advance(SECOND);
    assert_eq!(
        run.report(RejectionEvidence::SshUnverified),
        Ok(rejection.clone())
    );
    assert_eq!(run.adapter.state(), &run.ended_by(ManagementSsh));
    assert_eq!(run.known.rejections(), vec![rejection]);
    // No reconnect, with any key.
    for key in [host_key(1), host_key(9)] {
        assert!(matches!(
            run.connect(3, &key),
            Err(AdapterRefusal::InvalidStep {
                step: AdapterStep::Connect,
                ..
            })
        ));
    }
    assert_eq!(run.terminate_and_settle(), SETTLED);

    // Enrolled, before the runtime is confirmed: the run ends and goes no further.
    let mut run = Run::enrolled(Kind::Vm, KnownHosts::new(), &host_key(1));
    run.report(RejectionEvidence::SshAlgorithmNotOffered)
        .unwrap();
    assert_eq!(run.adapter.state(), &run.ended_by(ManagementSsh));
    let instance = run.adapter.instance().unwrap().instance;
    let offer = run
        .world
        .remote_offer(instance, ExecutionCategory::VmSandbox);
    assert!(matches!(
        run.adapter.confirm_runtime(&offer, None),
        Err(AdapterRefusal::InvalidStep {
            step: AdapterStep::ConfirmRuntime,
            ..
        })
    ));
    assert_eq!(run.terminate_and_settle(), SETTLED);

    // Authority that already ended keeps its reason; the rejection is still recorded.
    let mut run = Run::running(Kind::Vm);
    let identity = run.identity();
    run.world.advance(11 * MINUTE);
    assert!(run.adapter.check_authority(&mut run.authority).is_err());
    let ended = run.adapter.state().clone();
    assert!(matches!(
        ended,
        AdapterState::AuthorityEnded {
            reason: AuthorityEnd::LeaseRefused { .. }
        }
    ));
    run.report(RejectionEvidence::SshUnverified).unwrap();
    assert_eq!(run.adapter.state(), &ended);
    assert!(run
        .known
        .rejection(&identity.host, identity.enrollment)
        .is_some());

    // A host retired outside the run: nothing is recorded, and authority still ends.
    let mut run = Run::running(Kind::Vm);
    let identity = run.identity();
    run.known.retire(&identity.host);
    assert_eq!(
        run.report(RejectionEvidence::SshUnverified),
        Err(AdapterRefusal::RejectionNotRecorded {
            refusal: RejectionRefusal::NotCurrent {
                host: identity.host,
                current: None,
                presented: identity.enrollment,
            }
        })
    );
    assert_eq!(run.adapter.state(), &run.ended_by(ManagementSsh));
    assert!(!run.host_honours());
    assert!(run.known.rejections().is_empty());

    // Before any enrollment there is nothing to reject.
    let mut run = Run::provisioned(Kind::Vm, KnownHosts::new());
    assert_eq!(
        run.report(RejectionEvidence::SshUnverified),
        Err(AdapterRefusal::InvalidStep {
            state: AdapterState::Provisioned,
            step: AdapterStep::ReportHostKeyMismatch
        })
    );
    assert!(run.known.rejections().is_empty());
}

#[test]
fn after_a_rejection_every_check_refuses_the_enrollment_and_the_old_key() {
    let mut run = Run::running(Kind::Vm);
    let identity = run.identity();
    let (host, generation) = (identity.host, identity.enrollment);
    let management = management_identity(&run.enrollment());
    let shell = ExecutionContext::RemoteHostShell { host };
    let command = RemoteCommand::new(
        ProgramPath::new("/opt/yougori/bin/yougori-remote").unwrap(),
        OptionTerminator::DoubleDash,
    )
    .flag("--collect-logs")
    .unwrap();
    let invocation = |known: &KnownHosts| {
        RemoteInvocation::new(
            &management,
            known,
            ManagementAction::CollectLogs,
            shell,
            &command,
        )
        .map(|_| ())
    };
    assert_eq!(management.check_current(&run.known), Ok(()));
    assert_eq!(invocation(&run.known), Ok(()));

    // Another observer rejects the enrollment, through a shared reference.
    let shared: &KnownHosts = &run.known;
    let rejection = shared
        .record_rejection(
            &host,
            generation,
            ManagementSsh,
            RejectionEvidence::SshUnverified,
            run.world.now(),
        )
        .unwrap();
    let rejected = HostKeyRefusal::Rejected { host, generation };
    for key in [host_key(1), host_key(9)] {
        assert_eq!(run.known.verify(&host, &key), Err(rejected.clone()));
    }
    assert_eq!(run.known.enrollment(&host), None);
    let refusal = ManagementRefusal::HostKeyRejected { host, generation };
    assert_eq!(management.check_current(&run.known), Err(refusal.clone()));
    assert_eq!(
        invocation(&run.known),
        Err(ArgvRefusal::Management { refusal })
    );
    // A copy of the book holds it too.
    let copy = run.known.clone();
    assert_eq!(copy, run.known);
    assert_eq!(copy.verify(&host, &host_key(1)), Err(rejected.clone()));

    // A reconnect with the old, enrolled key is refused and ends authority at once.
    assert!(run.host_honours());
    assert_eq!(
        run.connect(2, &host_key(1)),
        Err(AdapterRefusal::HostKey {
            refusal: rejected.clone()
        })
    );
    assert_eq!(run.adapter.state(), &run.ended_by(ManagementSsh));
    assert!(!run.host_honours());
    // The first record stands.
    assert_eq!(run.known.rejections(), vec![rejection]);
}

#[test]
fn a_changed_key_against_a_host_enrolled_again_is_stale_and_records_nothing() {
    let mut run = Run::running(Kind::Vm);
    let identity = run.identity();
    run.known.retire(&identity.host);
    let current = run
        .known
        .enroll(
            identity.host,
            &host_key(2),
            provider_api(&host_key(2)),
            EnrollmentPolicy::default(),
            run.world.now(),
        )
        .unwrap();
    // The run's key is not the current one, but it is the run that is stale: the new
    // enrollment is not rejected and the run's authority is left to its expiry.
    assert!(matches!(
        run.connect(2, &host_key(1)),
        Err(AdapterRefusal::HostKey {
            refusal: HostKeyRefusal::Changed { .. }
        })
    ));
    assert_eq!(run.adapter.state(), &AdapterState::Running);
    assert!(run.known.rejections().is_empty());
    assert_eq!(run.known.enrollment(&identity.host), Some(&current));
}

#[test]
fn re_enrollment_makes_a_new_generation_that_works() {
    let mut run = Run::running(Kind::Vm);
    let old = run.identity();
    let host = old.host;
    let management = management_identity(&run.enrollment());
    assert!(run.connect(2, &host_key(9)).is_err());
    assert!(run.known.rejection(&host, old.enrollment).is_some());
    let now = run.world.now();
    let permitted = EnrollmentPolicy {
        allow_first_use: true,
    };
    // Never first use, and never on evidence for another key.
    assert_eq!(
        run.known.enroll(
            host,
            &host_key(9),
            EnrollmentEvidence::FirstUse,
            permitted,
            now
        ),
        Err(EnrollmentRefusal::NotFirstUse { host })
    );
    assert!(matches!(
        run.known.enroll(
            host,
            &host_key(9),
            provider_api(&host_key(2)),
            permitted,
            now
        ),
        Err(EnrollmentRefusal::EvidenceMismatch { .. })
    ));
    assert_eq!(run.known.enrollment(&host), None);

    // A new run on the same host enrolls it again through the provider's API and runs.
    let known = std::mem::take(&mut run.known);
    let mut next = Run::running_with(Kind::Vm, known, &host_key(2));
    let renewed = next.identity();
    assert_eq!(renewed.host, host);
    assert!(renewed.enrollment > old.enrollment);
    assert!(next.host_honours());
    assert_eq!(
        next.known
            .verify(&host, &host_key(2))
            .map(|enrollment| enrollment.generation),
        Ok(renewed.enrollment)
    );
    assert_eq!(
        management_identity(&next.enrollment()).check_current(&next.known),
        Ok(())
    );
    // The old key and identities stay refused; the record is kept.
    assert!(matches!(
        next.known.verify(&host, &host_key(1)),
        Err(HostKeyRefusal::Changed { .. })
    ));
    assert_eq!(
        management.check_current(&next.known),
        Err(ManagementRefusal::HostKeyRejected {
            host,
            generation: old.enrollment
        })
    );
    assert!(next.known.rejection(&host, old.enrollment).is_some());
    assert_eq!(next.known.rejection(&host, renewed.enrollment), None);
    assert_eq!(next.known.rejections().len(), 1);
}

#[test]
fn a_rejection_names_the_current_enrollment_and_the_first_record_is_kept() {
    let strict = EnrollmentPolicy::default();
    let mut known = KnownHosts::new();
    let first = known
        .enroll(
            host_id(1),
            &host_key(1),
            provider_api(&host_key(1)),
            strict,
            at(1),
        )
        .unwrap();
    let later = first.generation.next().unwrap();
    assert_eq!(
        known.record_rejection(
            &host_id(1),
            later,
            ControlConnect,
            RejectionEvidence::SshUnverified,
            at(2)
        ),
        Err(RejectionRefusal::NotCurrent {
            host: host_id(1),
            current: Some(first.generation),
            presented: later,
        })
    );
    assert_eq!(
        known.record_rejection(
            &host_id(2),
            first.generation,
            ControlConnect,
            RejectionEvidence::SshUnverified,
            at(2)
        ),
        Err(RejectionRefusal::NotCurrent {
            host: host_id(2),
            current: None,
            presented: first.generation,
        })
    );
    assert!(known.rejections().is_empty());
    assert_eq!(known.verify(&host_id(1), &host_key(1)), Ok(&first));
    let recorded = known
        .record_rejection(
            &host_id(1),
            first.generation,
            ControlConnect,
            RejectionEvidence::PresentedKey {
                presented: host_key(9).fingerprint(),
            },
            at(3),
        )
        .unwrap();
    assert_eq!(
        known.record_rejection(
            &host_id(1),
            first.generation,
            ManagementSsh,
            RejectionEvidence::SshUnverified,
            at(4)
        ),
        Ok(recorded.clone())
    );
    // The same key comes back only through a supported flow, under a new generation.
    let second = known
        .enroll(
            host_id(1),
            &host_key(1),
            provider_api(&host_key(1)),
            strict,
            at(5),
        )
        .unwrap();
    assert!(second.generation > first.generation);
    assert_eq!(known.verify(&host_id(1), &host_key(1)), Ok(&second));
    // A rejected enrollment that is then retired keeps its record.
    known
        .record_rejection(
            &host_id(1),
            second.generation,
            ManagementSsh,
            RejectionEvidence::SshAlgorithmNotOffered,
            at(6),
        )
        .unwrap();
    assert_eq!(known.retire(&host_id(1)), Some(second.clone()));
    assert_eq!(
        known.verify(&host_id(1), &host_key(1)),
        Err(HostKeyRefusal::NotEnrolled { host: host_id(1) })
    );
    let generations: Vec<_> = known
        .rejections()
        .iter()
        .map(HostKeyRejection::generation)
        .collect();
    assert_eq!(generations, vec![first.generation, second.generation]);
    assert_eq!(
        known.rejection(&host_id(1), first.generation),
        Some(recorded)
    );
}

#[test]
fn a_provider_container_run_ends_the_same_way() {
    // At connect.
    let mut run = Run::running(Kind::Container);
    assert!(run.host_honours());
    assert!(matches!(
        run.connect(2, &host_key(9)),
        Err(AdapterRefusal::HostKey {
            refusal: HostKeyRefusal::Changed { .. }
        })
    ));
    assert_eq!(run.adapter.state(), &run.ended_by(ControlConnect));
    // The labelled record is revoked, so its grant is never honoured again.
    assert!(!run.host_honours());
    assert!(run.authority.check_labelled(&pod_execution()).is_err());
    assert_eq!(run.terminate_and_settle(), SETTLED);
    assert!(!run.acknowledged(RevocationMilestone::VmStopped));
    assert!(run.acknowledged(RevocationMilestone::ProviderStoppedBilling));

    // Reported by management.
    let mut run = Run::running(Kind::Container);
    let identity = run.identity();
    run.report(RejectionEvidence::SshKeyChanged { printed: None })
        .unwrap();
    assert_eq!(run.adapter.state(), &run.ended_by(ManagementSsh));
    assert!(!run.host_honours());
    assert!(run.authority.check_labelled(&pod_execution()).is_err());
    assert_eq!(
        run.known.verify(&identity.host, &host_key(1)),
        Err(HostKeyRefusal::Rejected {
            host: identity.host,
            generation: identity.enrollment
        })
    );
    assert_eq!(run.terminate_and_settle(), SETTLED);
}

#[test]
fn the_rejection_record_round_trips_strictly() {
    let mut known = KnownHosts::new();
    let enrollment = known
        .enroll(
            host_id(1),
            &host_key(1),
            provider_api(&host_key(1)),
            EnrollmentPolicy::default(),
            at(5),
        )
        .unwrap();
    for evidence in [
        RejectionEvidence::PresentedKey {
            presented: host_key(9).fingerprint(),
        },
        RejectionEvidence::SshKeyChanged {
            printed: Some(printed()),
        },
        RejectionEvidence::SshKeyChanged { printed: None },
        RejectionEvidence::SshAlgorithmNotOffered,
        RejectionEvidence::SshUnverified,
    ] {
        for observer in [ControlConnect, ManagementSsh] {
            let record = HostKeyRejection {
                enrollment: enrollment.clone(),
                observer,
                evidence: evidence.clone(),
                rejected_at: at(7),
            };
            let value = serde_json::to_value(&record).unwrap();
            assert_eq!(
                serde_json::from_value::<HostKeyRejection>(value.clone()).unwrap(),
                record
            );
            for (path, field) in [
                (None, "lease"),
                (Some("evidence"), "note"),
                (Some("enrollment"), "replaced_by"),
            ] {
                let mut tampered = value.clone();
                let target = match path {
                    Some(path) => &mut tampered[path],
                    None => &mut tampered,
                };
                target[field] = serde_json::json!(1);
                assert!(
                    serde_json::from_value::<HostKeyRejection>(tampered).is_err(),
                    "{path:?} {field}"
                );
            }
        }
    }

    let record = known
        .record_rejection(
            &host_id(1),
            enrollment.generation,
            ManagementSsh,
            RejectionEvidence::SshKeyChanged {
                printed: Some(printed()),
            },
            at(7),
        )
        .unwrap();
    let value = serde_json::to_value(&record).unwrap();
    assert_eq!(value["observer"], "management_ssh");
    assert_eq!(
        value["evidence"],
        serde_json::json!({"evidence": "ssh_key_changed", "printed": OPENSSH_FINGERPRINT})
    );
    assert_eq!(
        value["enrollment"]["generation"],
        serde_json::json!(enrollment.generation.get())
    );
    // A unit evidence variant refuses fields beside its tag.
    assert!(
        serde_json::from_value::<RejectionEvidence>(serde_json::json!({
            "evidence": "ssh_unverified",
            "printed": OPENSSH_FINGERPRINT,
        }))
        .is_err()
    );
    assert!(serde_json::from_value::<RejectionObserver>(serde_json::json!("operator")).is_err());
    // Printed fingerprints are bounded printable ASCII without spaces, read back too.
    assert!(PrintedFingerprint::new("A".repeat(MAX_PRINTED_FINGERPRINT_BYTES)).is_ok());
    for bad in [
        "",
        "SHA256: x",
        "SHA256:\tx",
        "SHA256:\u{e9}",
        &"A".repeat(MAX_PRINTED_FINGERPRINT_BYTES + 1),
    ] {
        assert!(PrintedFingerprint::new(bad).is_err(), "{bad:?}");
        let mut tampered = value.clone();
        tampered["evidence"]["printed"] = serde_json::json!(bad);
        assert!(
            serde_json::from_value::<HostKeyRejection>(tampered).is_err(),
            "{bad:?}"
        );
    }
    // The reason an adapter ends with names the rejected enrollment and its observer.
    let reason = serde_json::to_value(AuthorityEnd::HostKeyRejected {
        host: host_id(1),
        generation: enrollment.generation,
        observer: ControlConnect,
    })
    .unwrap();
    assert_eq!(reason["reason"], "host_key_rejected");
    assert_eq!(reason["observer"], "control_connect");
}
