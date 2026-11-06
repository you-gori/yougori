//! M16C: management calls bound to the remote VM adapter (VM-W41, the library halves of
//! M16's lifecycle wiring; docs/combined-gpu-memory-and-vm-sandbox-plan.md, VM part §6.2,
//! §6.3; VM-W41 acceptance "remote reconnect cannot revive expired authority; capability
//! evidence distinguishes host shell from VM workload"; VM-D5, VM-D14).
//!
//! [`ManagementChannel`] runs V12's management invocations through an [`SshPort`] (in
//! production [`ProcessSshPort`](super::ProcessSshPort)) for one run of a
//! [`RemoteVmAdapter`], and only as far as that run allows. Before anything is rendered:
//!
//! - The identity file is still owner-only (M16D, `protection`'s check), so a key file
//!   another account could read or replace is never handed to the client.
//! - The adapter has a provider instance and an enrolled identity, the management identity
//!   and the invocation are for that instance's host, and the host's current enrollment is
//!   still the identity the adapter enrolled (a re-enrollment outside the adapter is
//!   refused as stale).
//! - The invocation's context belongs to the run's kind: a VM run is managed through the
//!   host shell or its VM workload, a provider-container run only inside its container
//!   (VM-D5: a container is never managed as if it were a VM host). V12 runs VM lifecycle
//!   actions in the host shell only, so a provider-container run gets the Jupyter password
//!   and logs here and nothing else; it is stopped through the provider.
//! - The adapter's state allows the action ([`ManagementChannel::call`] has the table).
//!   The VM is launched only on a per-sandbox-VM path and only before its runtime is
//!   confirmed, because V12 confirms that runtime from management evidence of the running
//!   VM; a launch after confirmation would start another VM than the one confirmed, so it
//!   needs a new run. Launches before confirmation are not counted here: a failed launch
//!   may be retried, and the confirmation names exactly one VM. While the run holds
//!   delegated authority, supervising and the Jupyter password (VM-D14) first check the
//!   host's authority through the adapter: authority the host let expire ends there, as
//!   V12 ends it, and nothing runs. Terminating and collecting logs stay possible after
//!   authority ended, until the provider confirms termination. So no reconnect and no
//!   management call revives ended authority.
//! - A call that needs authority must also end within it: the limits' deadline from now
//!   may not pass the delegation's expiry. The remote side keeps its own copy of the
//!   lease (V12's `remote_authority_bound`); this keeps the host from starting a call
//!   that could outlast the authority it was checked under.
//!
//! After the run: a host key other than the enrolled one ([`SshOutcome::HostKeyMismatch`])
//! is reported through [`RemoteVmAdapter::report_host_key_mismatch`], which records the
//! rejection of the enrollment in V12's [`KnownHosts`] and ends delegated authority at
//! once, and the channel runs nothing more, not even terminate or logs: whoever answers is
//! not the enrolled host, and cleanup goes through the provider. Another channel for the
//! same enrollment is refused too, since the rejected enrollment is no longer the host's
//! current one.
//!
//! Evidence (VM-W41). A call's result is V12 [`RemoteCapabilityEvidence`] only through
//! this module, always in the invocation's own context and under the enrollment the call
//! was rendered under, so V12's [`RemoteCapabilityEvidence::supports`] keeps a host shell
//! or a provider container from standing for a VM workload:
//!
//! - [`ManagementCall::command_ran`]: a command ran (`ShellCommand`), for any remote exit.
//! - [`ManagementChannel::probe_hardware_virtualization`]: `/usr/bin/test -c /dev/kvm` in
//!   the host shell; exit 0 is available, 1 is not, anything else is no evidence. It
//!   shows that the device node exists, not that the launching account may open it.
//!
//! Not here: a probe that the VM runs hardware accelerated (`VmRunning`), which V12 needs
//! to confirm a per-sandbox VM and which depends on the remote agent's design; the
//! provider transport; the control session's transport; key storage; and the product
//! paths (`runtime/cloud/`).

use std::fmt;

use serde::Serialize;

use super::invocation::{render_invocation, IdentityFile, SshLimits, SshRenderRefusal, SshRun};
use super::known_hosts::KnownHostsFile;
use super::outcome::{HostKeyEvidence, SshOutcome, SshPort};
use super::protection::{check_identity_file, IdentityFileRefusal};
use crate::foundation::ids::{Clock, MonotonicTime};
use crate::sandbox_contract::remote::{
    AdapterRefusal, AdapterState, ArgvRefusal, ExecutionContext, HostAuthority, HostEnrollment,
    HostKeyFingerprint, KnownHosts, ManagementAction, ManagementIdentity, OptionTerminator,
    PrintedFingerprint, ProgramPath, RejectionEvidence, RemoteCapability, RemoteCapabilityEvidence,
    RemoteCommand, RemoteHostId, RemoteIdentity, RemoteInvocation, RemoteVmAdapter, VmPath,
};

/// The program the hardware-virtualization probe runs on the remote host.
pub const TEST_PROGRAM: &str = "/usr/bin/test";

/// The device node whose presence the hardware-virtualization probe checks.
pub const KVM_DEVICE: &str = "/dev/kvm";

/// What the adapter's state lets an action do.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Gate {
    Refuse,
    Run,
    /// Runs only while the host's authority over the run is current, and only if the
    /// call ends within it.
    RunWithinAuthority,
}

/// The table of [`ManagementChannel::call`].
fn gate(action: ManagementAction, state: &AdapterState, per_sandbox_vm: bool) -> Gate {
    use ManagementAction::{
        CollectLogs, LaunchVm, ReplaceJupyterPassword, SuperviseVm, TerminateVm,
    };
    match (state, action) {
        (AdapterState::IdentityEnrolled, LaunchVm) if per_sandbox_vm => Gate::Run,
        (AdapterState::IdentityEnrolled, SuperviseVm | CollectLogs | TerminateVm) => Gate::Run,
        (
            AdapterState::RuntimeConfirmed,
            SuperviseVm | ReplaceJupyterPassword | CollectLogs | TerminateVm,
        ) => Gate::Run,
        (AdapterState::Running, SuperviseVm | ReplaceJupyterPassword) => Gate::RunWithinAuthority,
        (
            AdapterState::Running | AdapterState::AuthorityEnded { .. } | AdapterState::Terminating,
            CollectLogs | TerminateVm,
        ) => Gate::Run,
        _ => Gate::Refuse,
    }
}

/// Whether `context` belongs to a run of this kind: a VM run's host shell or VM
/// workload, or a provider-container run's container.
pub(super) fn context_fits(context: ExecutionContext, vm_run: bool) -> bool {
    match context {
        ExecutionContext::RemoteHostShell { .. } | ExecutionContext::VmWorkload { .. } => vm_run,
        ExecutionContext::ProviderContainer { .. } => !vm_run,
    }
}

/// Why a management call was not started. Nothing was rendered or run.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ManagementCallRefusal {
    /// An earlier call on this channel met a host key other than the enrolled one; the
    /// channel runs nothing more.
    HostKeyRejected {
        host: RemoteHostId,
        enrolled: HostKeyFingerprint,
    },
    /// The channel's identity file is missing or not owner-only.
    IdentityFile { refusal: IdentityFileRefusal },
    /// The adapter has no provider instance or no enrolled identity yet.
    NotEnrolled,
    /// The management identity or the invocation is for another host than the run's.
    WrongHost {
        run: RemoteHostId,
        other: RemoteHostId,
    },
    /// The host's current enrollment is not the identity the adapter enrolled.
    StaleIdentity,
    /// The invocation's context does not belong to this run's kind.
    ContextForAnotherKind { context: ExecutionContext },
    /// The adapter's state does not allow the action.
    NotNow {
        action: ManagementAction,
        state: AdapterState,
    },
    /// The host's authority over the run is no longer current; the adapter ended it.
    /// Boxed: V12's refusal takes over 200 bytes, every other variant less than 128.
    Authority { refusal: Box<AdapterRefusal> },
    /// The call could run past the delegation's expiry.
    AuthorityEndsFirst {
        expires_at: MonotonicTime,
        deadline_at: MonotonicTime,
    },
    /// A probe's invocation could not be built.
    Invocation { refusal: ArgvRefusal },
    /// The invocation could not be rendered.
    Render { refusal: SshRenderRefusal },
}

impl fmt::Display for ManagementCallRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HostKeyRejected { .. } => f.write_str(
                "an earlier management call met a host key other than the enrolled one, so \
                 this channel runs nothing more",
            ),
            Self::IdentityFile { refusal } => write!(f, "{refusal}"),
            Self::NotEnrolled => f.write_str("the remote run has no enrolled host yet"),
            Self::WrongHost { .. } => {
                f.write_str("the management call is for another host than the remote run's")
            }
            Self::StaleIdentity => f.write_str(
                "the host's current enrollment is not the identity the remote run enrolled",
            ),
            Self::ContextForAnotherKind { .. } => {
                f.write_str("the management call runs in a context foreign to this remote run")
            }
            Self::NotNow { action, .. } => {
                write!(
                    f,
                    "the remote run does not allow {action:?} in its current state"
                )
            }
            Self::Authority { refusal } => write!(f, "{refusal}"),
            Self::AuthorityEndsFirst { .. } => f.write_str(
                "the management call could run past the expiry of the remote run's authority",
            ),
            Self::Invocation { refusal } => write!(f, "{refusal}"),
            Self::Render { refusal } => write!(f, "{refusal}"),
        }
    }
}

impl std::error::Error for ManagementCallRefusal {}

/// The host key an earlier call met instead of the enrolled one.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RejectedHostKey {
    /// The run's host.
    pub host: RemoteHostId,
    /// The fingerprint of the key enrolled for it.
    pub enrolled: HostKeyFingerprint,
    /// What the client reported about the key it was shown.
    pub evidence: HostKeyEvidence,
}

/// One management call that ran: what it did, where, under which enrollment, and what
/// the client reported.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ManagementCall {
    /// The action the invocation performs.
    pub action: ManagementAction,
    /// Where the invocation ran.
    pub context: ExecutionContext,
    /// The host's enrollment the call was rendered under.
    pub enrollment: HostEnrollment,
    /// What the port reported and how it was classified.
    pub run: SshRun,
    /// When the run was reported, on the host authority's clock.
    pub ended_at: MonotonicTime,
}

impl ManagementCall {
    /// Evidence that a command ran in the call's context, for any remote exit status;
    /// `None` when the outcome does not show that the remote command ran.
    pub fn command_ran(&self) -> Option<RemoteCapabilityEvidence> {
        matches!(self.run.outcome, SshOutcome::RemoteExit { .. })
            .then(|| self.evidence(RemoteCapability::ShellCommand))
    }

    fn evidence(&self, capability: RemoteCapability) -> RemoteCapabilityEvidence {
        RemoteCapabilityEvidence::observed(
            &self.enrollment,
            self.context,
            capability,
            self.ended_at,
        )
    }
}

/// A probe's call and the evidence it gave, if any.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProbeResult {
    /// The call the probe made.
    pub call: ManagementCall,
    /// The capability the outcome shows; `None` when it shows none.
    pub evidence: Option<RemoteCapabilityEvidence>,
}

/// Management calls for one remote run over one port, `known_hosts` file and identity
/// file; see the module notes.
#[derive(Debug)]
pub struct ManagementChannel<P: SshPort> {
    port: P,
    known_hosts: KnownHostsFile,
    identity_file: IdentityFile,
    limits: SshLimits,
    rejected: Option<RejectedHostKey>,
}

impl<P: SshPort> ManagementChannel<P> {
    /// A channel that renders with `known_hosts`, `identity_file` and `limits` and runs
    /// through `port`. Rendering checks the files against the identity on every call.
    pub fn new(
        port: P,
        known_hosts: KnownHostsFile,
        identity_file: IdentityFile,
        limits: SshLimits,
    ) -> Self {
        Self {
            port,
            known_hosts,
            identity_file,
            limits,
            rejected: None,
        }
    }

    /// The port calls run through.
    pub fn port(&self) -> &P {
        &self.port
    }

    /// The time and output limits every call is rendered and checked with.
    pub fn limits(&self) -> SshLimits {
        self.limits
    }

    /// The host key that closed this channel, if one did.
    pub fn rejected(&self) -> Option<&RejectedHostKey> {
        self.rejected.as_ref()
    }

    /// Runs `invocation` for the run `adapter` manages, after the checks in the module
    /// notes. By the adapter's state:
    ///
    /// | State | Runs | Runs within current authority | Refused |
    /// |---|---|---|---|
    /// | identity enrolled | launch (per-sandbox VM only), supervise, logs, terminate | | Jupyter password |
    /// | runtime confirmed | supervise, Jupyter password, logs, terminate | | launch |
    /// | running | logs, terminate | supervise, Jupyter password | launch |
    /// | authority ended, terminating | logs, terminate | | the rest |
    /// | any other | | | everything |
    pub fn call<C: Clock>(
        &mut self,
        adapter: &mut RemoteVmAdapter<C>,
        authority: &mut dyn HostAuthority,
        known: &KnownHosts,
        identity: &ManagementIdentity,
        invocation: &RemoteInvocation,
    ) -> Result<ManagementCall, ManagementCallRefusal> {
        let enrollment = self.admit(
            adapter,
            authority,
            known,
            identity,
            invocation.action(),
            invocation.context(),
        )?;
        self.run_admitted(adapter, authority, known, identity, invocation, enrollment)
    }

    /// Asks the run's host shell whether it has the KVM device node: exit 0 is
    /// `HardwareVirtualization { available: true }`, exit 1 is `available: false`, and any
    /// other outcome gives no evidence. It runs as a supervise call, so the same table
    /// applies, and it is admitted before its invocation is built.
    pub fn probe_hardware_virtualization<C: Clock>(
        &mut self,
        adapter: &mut RemoteVmAdapter<C>,
        authority: &mut dyn HostAuthority,
        known: &KnownHosts,
        identity: &ManagementIdentity,
    ) -> Result<ProbeResult, ManagementCallRefusal> {
        let enrollment = self.admit(
            adapter,
            authority,
            known,
            identity,
            ManagementAction::SuperviseVm,
            ExecutionContext::RemoteHostShell {
                host: identity.host(),
            },
        )?;
        let invocation = hardware_virtualization_probe(identity, known)
            .map_err(|refusal| ManagementCallRefusal::Invocation { refusal })?;
        let call =
            self.run_admitted(adapter, authority, known, identity, &invocation, enrollment)?;
        let available = match call.run.outcome {
            SshOutcome::RemoteExit { code: 0 } => Some(true),
            SshOutcome::RemoteExit { code: 1 } => Some(false),
            _ => None,
        };
        let evidence = available
            .map(|available| call.evidence(RemoteCapability::HardwareVirtualization { available }));
        Ok(ProbeResult { call, evidence })
    }

    /// The checks before rendering, for `action` in `context`; the host's current
    /// enrollment when they pass.
    fn admit<C: Clock>(
        &self,
        adapter: &mut RemoteVmAdapter<C>,
        authority: &mut dyn HostAuthority,
        known: &KnownHosts,
        identity: &ManagementIdentity,
        action: ManagementAction,
        context: ExecutionContext,
    ) -> Result<HostEnrollment, ManagementCallRefusal> {
        if let Some(rejected) = &self.rejected {
            return Err(ManagementCallRefusal::HostKeyRejected {
                host: rejected.host,
                enrolled: rejected.enrolled,
            });
        }
        check_identity_file(self.identity_file.path())
            .map_err(|refusal| ManagementCallRefusal::IdentityFile { refusal })?;
        let (Some(instance), Some(enrolled)) = (adapter.instance(), adapter.identity()) else {
            return Err(ManagementCallRefusal::NotEnrolled);
        };
        let run = instance.host();
        for other in [identity.host(), context.host()] {
            if other != run {
                return Err(ManagementCallRefusal::WrongHost { run, other });
            }
        }
        let enrollment = known
            .enrollment(&run)
            .filter(|current| {
                RemoteIdentity::from_enrollment(current).digest() == enrolled.digest()
            })
            .ok_or(ManagementCallRefusal::StaleIdentity)?
            .clone();
        let selection = adapter.selection();
        if !context_fits(context, selection.is_vm_sandbox()) {
            return Err(ManagementCallRefusal::ContextForAnotherKind { context });
        }
        let per_sandbox_vm = selection.vm_path() == Some(VmPath::PerSandboxVm);
        match gate(action, adapter.state(), per_sandbox_vm) {
            Gate::Refuse => Err(ManagementCallRefusal::NotNow {
                action,
                state: adapter.state().clone(),
            }),
            Gate::Run => Ok(enrollment),
            Gate::RunWithinAuthority => {
                let delegation = adapter.check_authority(authority).map_err(|refusal| {
                    ManagementCallRefusal::Authority {
                        refusal: Box::new(refusal),
                    }
                })?;
                let expires_at = delegation.expires_at();
                // Past the clock's range the deadline saturates, and no expiry reaches it.
                let deadline_at = authority.now().saturating_add(self.limits.deadline());
                if deadline_at > expires_at {
                    return Err(ManagementCallRefusal::AuthorityEndsFirst {
                        expires_at,
                        deadline_at,
                    });
                }
                Ok(enrollment)
            }
        }
    }

    /// Renders and runs an admitted invocation under `enrollment`; a host-key mismatch
    /// closes the channel, and the adapter records the rejection and ends its authority.
    fn run_admitted<C: Clock>(
        &mut self,
        adapter: &mut RemoteVmAdapter<C>,
        authority: &mut dyn HostAuthority,
        known: &KnownHosts,
        identity: &ManagementIdentity,
        invocation: &RemoteInvocation,
        enrollment: HostEnrollment,
    ) -> Result<ManagementCall, ManagementCallRefusal> {
        let rendered = render_invocation(
            identity,
            known,
            &self.known_hosts,
            &self.identity_file,
            self.limits,
            invocation,
        )
        .map_err(|refusal| ManagementCallRefusal::Render { refusal })?;
        let run = rendered.run(&mut self.port);
        if let SshOutcome::HostKeyMismatch {
            host,
            enrolled,
            evidence,
        } = &run.outcome
        {
            // The call ran, so its result is returned whatever the adapter answers; the
            // adapter ends authority even when the rejection cannot be recorded.
            let _ =
                adapter.report_host_key_mismatch(known, authority, rejection_evidence(evidence));
            self.rejected = Some(RejectedHostKey {
                host: *host,
                enrolled: *enrolled,
                evidence: evidence.clone(),
            });
        }
        Ok(ManagementCall {
            action: invocation.action(),
            context: invocation.context(),
            enrollment,
            run,
            ended_at: authority.now(),
        })
    }
}

/// What the client reported about the host key, as V12's evidence of the rejection.
pub(super) fn rejection_evidence(evidence: &HostKeyEvidence) -> RejectionEvidence {
    match evidence {
        HostKeyEvidence::Changed { reported } => RejectionEvidence::SshKeyChanged {
            printed: reported
                .as_deref()
                .and_then(|text| PrintedFingerprint::new(text).ok()),
        },
        HostKeyEvidence::AlgorithmNotOffered => RejectionEvidence::SshAlgorithmNotOffered,
        HostKeyEvidence::Unverified => RejectionEvidence::SshUnverified,
    }
}

/// The hardware-virtualization probe for the identity's host: `/usr/bin/test -c
/// /dev/kvm` in the host shell, as a supervise call.
fn hardware_virtualization_probe(
    identity: &ManagementIdentity,
    known: &KnownHosts,
) -> Result<RemoteInvocation, ArgvRefusal> {
    let command = RemoteCommand::new(
        ProgramPath::new(TEST_PROGRAM)?,
        OptionTerminator::NotSupported,
    )
    .flag("-c")?
    .operand(KVM_DEVICE)?;
    RemoteInvocation::new(
        identity,
        known,
        ManagementAction::SuperviseVm,
        ExecutionContext::RemoteHostShell {
            host: identity.host(),
        },
        &command,
    )
}
