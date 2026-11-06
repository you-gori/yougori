//! [`RunPodProvider`]: V12's [`RemoteProviderPort`] for RunPod pods (VM-W39; VM-D5;
//! VM part §6.3 step 5, §7.6; VM-W31).
//!
//! A RunPod pod is a provider container: a labelled "remote runtime (provider
//! container), not a sandbox", never a per-sandbox VM. Every instance this transport
//! reports has the kind [`OfferingKind::ProviderContainer`], so V12 labels the run and its
//! labelled-runtime record (never a VM lease) carries the authority.
//!
//! The mapping, each outcome conservative:
//!
//! - `provision`: a request for another provider, a VM kind (RunPod has no per-sandbox
//!   VM) or an offering the catalog lacks is refused `NotCreated` with
//!   `InvalidRequest` before anything is sent, and [`RunPodProvider::last_problem`] names
//!   the reason. Otherwise `pod create` runs with the pod named after the attempt
//!   ([`PodName::for_attempt`]), the data center from the request's region and the GPU,
//!   count, cloud, image and disk from the catalog. `NotCreated` only when nothing was
//!   sent (no key, runpodctl not started, runpodctl refusing its own arguments) or the
//!   provider refused in words that say nothing was done; a timeout, an unreadable or
//!   oversized answer, any other failure after the request went out, or a created pod
//!   whose details cannot be read is `Unknown`. `Created` carries what `pod get` reports
//!   for the new pod: its data center, and the offering its GPU type and count map to, so
//!   V12's substitution check sees what was delivered.
//! - `find`: `pod list --all`, then the pods whose name carries the attempt's key and
//!   whose status is not `TERMINATED`. Exactly one is `Found`, with what `pod get`
//!   reports; none is `ConfirmedAbsent` only from a complete listing taken at least
//!   [`RunPodSettings::listing_settle`] after a create for the attempt was last sent (or
//!   after this transport was made, for an attempt it never sent), since RunPod may list
//!   a pod it has just made only later; several, an unreadable row, an unknown status on
//!   a matching pod, or a failed listing is `Unknown`.
//! - `terminate`: the pod is found by the digest V12 holds, from this transport's record
//!   of pods the provider reported, else from a listing (a pod not listed after the
//!   settle window, or listed as `TERMINATED`, is `AlreadyGone`). `pod delete` runs, then
//!   a follow-up listing decides: `Confirmed` only when the delete exited 0 and the
//!   complete listing no longer shows the pod as existing; `AlreadyGone` when the delete
//!   failed and the listing shows it gone (the provider's "not found" is its listing not
//!   holding the pod); `Failed` when nothing was sent or the provider refused the delete
//!   and the pod may still exist; `Unknown` otherwise.
//! - `final_bill`: always `Unavailable`, and nothing is called. RunPod reports a rate
//!   (`costPerHr`) and an account balance, never the final charge of one pod, so V12 keeps
//!   the run's whole reservation counted as spent until it is reconciled another way.
//!
//! Instance identity: [`pod_instance`], the digest of the pod id under
//! [`POD_INSTANCE_DOMAIN`]. Two further calls finish the provider half of M16 (a):
//! [`RunPodProvider::ssh_endpoint`] reports where the pod takes SSH (RunPod reports no
//! host key, so enrolling one rests on first use, which V12 records as an assumption),
//! and [`RunPodProvider::install_management_key`] puts the management public key on the
//! account, which RunPod installs in its pods.

use std::collections::BTreeMap;
use std::fmt;

use serde::Serialize;

use super::command::{CommandKind, RunPodCommand, RunPodSettings, RunpodctlInvocation};
use super::parse::{self, ListedPod, ParseProblem, PodDetail, Recognised, SshAddress};
use super::process::{RunpodctlOutput, RunpodctlPort};
use super::secret::{key_text, ApiKeySource, KeyUnavailable};
use super::values::{PodId, PodName, PodStatus, RunPodCatalog};
use crate::foundation::evidence::ProviderKind;
use crate::foundation::ids::{Clock, Digest, DigestBuilder, MonotonicTime};
use crate::sandbox_contract::destinations::{AddressRefused, Authority, HostAddressState};
use crate::sandbox_contract::remote::{
    AttemptId, BillingReport, LookupOutcome, OfferingKind, OfferingName, ProviderError,
    ProviderInstance, ProvisionOutcome, ProvisionRequest, RemoteProviderPort, TerminationOutcome,
    UncertainCause,
};
use crate::sandbox_contract::remote_ssh::{
    ManagementPublicKey, OutputStream, PortFailure, SshTermination,
};

/// Domain of [`pod_instance`].
pub const POD_INSTANCE_DOMAIN: &str = "yougori/sandbox/remote-provider/runpod-pod/v1";

/// The instance digest V12 holds for a pod: its id under [`POD_INSTANCE_DOMAIN`].
pub fn pod_instance(pod: &PodId) -> Digest {
    DigestBuilder::new(POD_INSTANCE_DOMAIN)
        .str(pod.as_str())
        .finish()
}

/// Why the last call ended as it did, when it did not simply succeed. Typed only: no
/// text runpodctl printed is kept, so nothing it echoed can leak through here.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "cause", rename_all = "snake_case")]
pub enum RunPodProblem {
    /// The request or instance is another provider's.
    ForeignProvider { provider: ProviderKind },
    /// A VM kind was asked for; RunPod has no per-sandbox VM (VM-D5).
    VmKindRefused { kind: OfferingKind },
    /// The offering is not in the catalog.
    UnknownOffering { offering: OfferingName },
    /// No key was given; nothing was sent.
    Key { reason: KeyUnavailable },
    /// runpodctl was not started; nothing was sent.
    NotStarted { command: CommandKind },
    /// runpodctl refused its own arguments; nothing was sent.
    ArgumentsRefused { command: CommandKind },
    /// The provider refused in words that say nothing was done.
    Refused {
        command: CommandKind,
        error: ProviderError,
    },
    /// runpodctl failed in words not recognised; `code` is its exit code, `None` when
    /// it reported success with an error object.
    Failed {
        command: CommandKind,
        code: Option<i32>,
    },
    /// runpodctl was stopped at its deadline.
    DeadlineReached { command: CommandKind },
    /// An output stream passed its bound; nothing was parsed.
    OutputOverBound {
        command: CommandKind,
        stream: OutputStream,
    },
    /// The port could not feed, read or watch runpodctl.
    PortFailed {
        command: CommandKind,
        failure: PortFailure,
    },
    /// runpodctl ended without an exit status.
    NoExitStatus { command: CommandKind },
    /// The answer could not be read.
    Unreadable {
        command: CommandKind,
        problem: ParseProblem,
    },
    /// No pod carries the key, but the listing is too soon after a create to be believed.
    ListingNotSettled,
    /// More than one existing pod carries the key.
    SeveralPods { count: u64 },
    /// The delete was answered, but the follow-up listing still shows the pod.
    StillListed { status: PodStatus },
    /// The key was added, but the follow-up listing does not show it.
    KeyNotListed,
    /// `pod get` reports the pod `TERMINATED` where an existing pod was expected.
    PodTerminated,
}

/// Where a pod takes SSH.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EndpointLookup {
    /// The pod is running and takes SSH at this public address and port.
    Ready {
        authority: Authority,
    },
    /// The pod exists but reports no SSH address yet.
    NotReady {
        status: PodStatus,
    },
    /// The reported address is one the destination rules refuse; it is not used.
    Refused {
        refusal: AddressRefused,
    },
    /// The provider confirms the pod no longer exists.
    Gone,
    Unknown {
        cause: UncertainCause,
    },
}

/// How putting the management public key on the account ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum KeyInstallOutcome {
    /// The account already lists the key; nothing was changed.
    AlreadyPresent,
    /// The key was added and the account now lists it.
    Installed,
    /// Nothing was installed: nothing was sent, or the provider refused.
    NotInstalled {
        error: ProviderError,
    },
    Unknown {
        cause: UncertainCause,
    },
}

/// Why a call did not answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Failure {
    /// Nothing was sent.
    NothingSent { error: ProviderError },
    /// The provider refused; nothing was done.
    Refused { error: ProviderError },
    /// Anything may have happened.
    Uncertain { cause: UncertainCause },
}

impl Failure {
    /// The cause a lookup reports: the provider could not be asked, or its answer is
    /// uncertain.
    fn lookup_cause(self) -> UncertainCause {
        match self {
            Self::NothingSent { .. } | Self::Refused { .. } => UncertainCause::ConnectionLost,
            Self::Uncertain { cause } => cause,
        }
    }
}

/// Where a pod V12 names by its digest stands.
enum Resolved {
    Pod(PodId),
    Gone,
    Unknown(UncertainCause),
}

/// The RunPod transport; see the module notes. `clock` times the settle window only.
pub struct RunPodProvider<P: RunpodctlPort, K: ApiKeySource, C: Clock> {
    port: P,
    keys: K,
    clock: C,
    catalog: RunPodCatalog,
    settings: RunPodSettings,
    started: MonotonicTime,
    /// When a create was last sent, or its pod id learned, per attempt.
    dispatched: BTreeMap<AttemptId, MonotonicTime>,
    /// Pods the provider reported, by the digest V12 holds.
    pods: BTreeMap<Digest, PodId>,
    last_problem: Option<RunPodProblem>,
}

impl<P: RunpodctlPort, K: ApiKeySource, C: Clock> fmt::Debug for RunPodProvider<P, K, C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RunPodProvider")
            .field("catalog", &self.catalog)
            .field("settings", &self.settings)
            .field("started", &self.started)
            .field("dispatched", &self.dispatched)
            .field("pods", &self.pods)
            .field("last_problem", &self.last_problem)
            .finish_non_exhaustive()
    }
}

impl<P: RunpodctlPort, K: ApiKeySource, C: Clock> RunPodProvider<P, K, C> {
    /// A transport over `port`, asking `keys` for the account key on every call, launching
    /// the offerings of `catalog`.
    pub fn new(
        port: P,
        keys: K,
        clock: C,
        catalog: RunPodCatalog,
        settings: RunPodSettings,
    ) -> Self {
        let started = clock.now();
        Self {
            port,
            keys,
            clock,
            catalog,
            settings,
            started,
            dispatched: BTreeMap::new(),
            pods: BTreeMap::new(),
            last_problem: None,
        }
    }

    /// Why the last call ended as it did; `None` after a plain success.
    pub fn last_problem(&self) -> Option<&RunPodProblem> {
        self.last_problem.as_ref()
    }

    /// The process port.
    pub fn port(&self) -> &P {
        &self.port
    }

    /// The process port, for a caller that inspects or reconfigures it.
    pub fn port_mut(&mut self) -> &mut P {
        &mut self.port
    }

    pub fn catalog(&self) -> &RunPodCatalog {
        &self.catalog
    }

    pub fn settings(&self) -> &RunPodSettings {
        &self.settings
    }

    /// Records `problem` unless the call already recorded one: the first cause stands.
    fn note(&mut self, problem: RunPodProblem) {
        if self.last_problem.is_none() {
            self.last_problem = Some(problem);
        }
    }

    /// Runs one command and returns its stdout when runpodctl answered without failing.
    fn call(&mut self, command: RunPodCommand) -> Result<Vec<u8>, Failure> {
        let kind = command.kind();
        let key = match self.keys.api_key() {
            Ok(key) => key,
            Err(reason) => {
                self.note(RunPodProblem::Key { reason });
                return Err(Failure::NothingSent {
                    error: ProviderError::Unauthorized,
                });
            }
        };
        if key_text(&key).is_none() {
            self.note(RunPodProblem::Key {
                reason: KeyUnavailable::Malformed,
            });
            return Err(Failure::NothingSent {
                error: ProviderError::Unauthorized,
            });
        }
        let invocation = RunpodctlInvocation::new(command, self.settings.limits(kind));
        let output = self.port.run(&invocation, &key);
        drop(key);
        self.classify(kind, &invocation, output)
    }

    fn classify(
        &mut self,
        command: CommandKind,
        invocation: &RunpodctlInvocation,
        output: RunpodctlOutput,
    ) -> Result<Vec<u8>, Failure> {
        let limits = invocation.limits();
        let ambiguous = Failure::Uncertain {
            cause: UncertainCause::AmbiguousResponse,
        };
        for (stream, bytes, max) in [
            (
                OutputStream::Stdout,
                &output.stdout,
                limits.max_stdout_bytes(),
            ),
            (
                OutputStream::Stderr,
                &output.stderr,
                limits.max_stderr_bytes(),
            ),
        ] {
            if u64::try_from(bytes.len()).map_or(true, |length| length > max) {
                self.note(RunPodProblem::OutputOverBound { command, stream });
                return Err(ambiguous);
            }
        }
        match output.termination {
            SshTermination::Exited { code: 0 } => match parse::error_object(&output.stdout) {
                None => Ok(output.stdout),
                Some(message) => Err(self.failed(command, None, &[message])),
            },
            SshTermination::Exited { code } => {
                let messages = parse::failure_messages(&output);
                Err(self.failed(command, Some(code), &messages))
            }
            SshTermination::NotStarted => {
                self.note(RunPodProblem::NotStarted { command });
                Err(Failure::NothingSent {
                    error: ProviderError::ProviderUnavailable,
                })
            }
            SshTermination::DeadlineReached => {
                self.note(RunPodProblem::DeadlineReached { command });
                Err(Failure::Uncertain {
                    cause: UncertainCause::Timeout,
                })
            }
            SshTermination::PortFailed { failure } => {
                self.note(RunPodProblem::PortFailed { command, failure });
                Err(ambiguous)
            }
            SshTermination::NoExitStatus => {
                self.note(RunPodProblem::NoExitStatus { command });
                Err(Failure::Uncertain {
                    cause: UncertainCause::ConnectionLost,
                })
            }
        }
    }

    fn failed(&mut self, command: CommandKind, code: Option<i32>, messages: &[String]) -> Failure {
        match parse::recognise_any(messages) {
            Some(Recognised::LocalRefusal) => {
                self.note(RunPodProblem::ArgumentsRefused { command });
                Failure::NothingSent {
                    error: ProviderError::InvalidRequest,
                }
            }
            Some(Recognised::Provider(error)) => {
                self.note(RunPodProblem::Refused { command, error });
                Failure::Refused { error }
            }
            None => {
                self.note(RunPodProblem::Failed { command, code });
                Failure::Uncertain {
                    cause: UncertainCause::AmbiguousResponse,
                }
            }
        }
    }

    fn unreadable(&mut self, command: CommandKind, problem: ParseProblem) -> UncertainCause {
        self.note(RunPodProblem::Unreadable { command, problem });
        UncertainCause::AmbiguousResponse
    }

    /// Whether a pod missing from a listing taken now is believed absent, for an attempt
    /// last sent at `since` (this transport's start when it never sent one).
    fn absence_settled(&self, since: Option<MonotonicTime>) -> bool {
        let since = since.unwrap_or(self.started);
        self.clock.now() >= since.saturating_add(self.settings.listing_settle)
    }

    /// Every pod of the account, from a complete listing.
    fn listing(&mut self) -> Result<Vec<ListedPod>, UncertainCause> {
        let stdout = self
            .call(RunPodCommand::ListPods)
            .map_err(Failure::lookup_cause)?;
        parse::pod_listing(&stdout)
            .map_err(|problem| self.unreadable(CommandKind::ListPods, problem))
    }

    /// What `pod get` reports about `pod`.
    fn detail(&mut self, pod: &PodId) -> Result<PodDetail, UncertainCause> {
        let stdout = self
            .call(RunPodCommand::GetPod { pod: pod.clone() })
            .map_err(Failure::lookup_cause)?;
        parse::pod_detail(&stdout, pod)
            .map_err(|problem| self.unreadable(CommandKind::GetPod, problem))
    }

    /// The instance `pod` is, as the provider reports it, for `name`'s attempt and the
    /// `requested` offering.
    fn delivered(
        &mut self,
        pod: &PodId,
        name: &PodName,
        requested: &OfferingName,
    ) -> Result<ProviderInstance, UncertainCause> {
        let detail = self.detail(pod)?;
        if !detail
            .name
            .as_deref()
            .is_some_and(|listed| name.carried_by(listed))
        {
            return Err(self.unreadable(CommandKind::GetPod, ParseProblem::NameWithoutKey));
        }
        if !detail.status.exists() {
            self.note(RunPodProblem::PodTerminated);
            return Err(UncertainCause::AmbiguousResponse);
        }
        let delivered = detail
            .delivered()
            .map_err(|problem| self.unreadable(CommandKind::GetPod, problem))?;
        let offering = self
            .catalog
            .delivered_offering(requested, &delivered.gpu, delivered.gpu_count)
            .ok_or(UncertainCause::AmbiguousResponse)?;
        Ok(ProviderInstance {
            provider: ProviderKind::RunPod,
            region: delivered.region,
            offering,
            kind: OfferingKind::ProviderContainer,
            instance: pod_instance(pod),
        })
    }

    /// Finds the pod V12 names by `instance`.
    fn resolve(&mut self, instance: &Digest) -> Resolved {
        if let Some(pod) = self.pods.get(instance) {
            return Resolved::Pod(pod.clone());
        }
        let rows = match self.listing() {
            Ok(rows) => rows,
            Err(cause) => return Resolved::Unknown(cause),
        };
        match rows.iter().find(|row| pod_instance(&row.id) == *instance) {
            Some(ListedPod {
                id,
                status: Some(status),
                ..
            }) => {
                if status.exists() {
                    self.pods.insert(*instance, id.clone());
                    Resolved::Pod(id.clone())
                } else {
                    Resolved::Gone
                }
            }
            Some(ListedPod { status: None, .. }) => Resolved::Unknown(
                self.unreadable(CommandKind::ListPods, ParseProblem::UnknownStatus),
            ),
            None if self.absence_settled(None) => Resolved::Gone,
            None => {
                self.note(RunPodProblem::ListingNotSettled);
                Resolved::Unknown(UncertainCause::AmbiguousResponse)
            }
        }
    }

    /// Whether a complete listing still shows `pod` as existing.
    fn still_exists(&mut self, pod: &PodId) -> Result<Option<PodStatus>, UncertainCause> {
        let rows = self.listing()?;
        match rows.into_iter().find(|row| row.id == *pod) {
            None => Ok(None),
            Some(ListedPod {
                status: Some(status),
                ..
            }) => Ok(status.exists().then_some(status)),
            Some(ListedPod { status: None, .. }) => {
                Err(self.unreadable(CommandKind::ListPods, ParseProblem::UnknownStatus))
            }
        }
    }

    /// Where the pod V12 names by `instance` takes SSH, with the address judged against
    /// `host`'s own addresses. RunPod reports no host key; see the module notes.
    pub fn ssh_endpoint(
        &mut self,
        instance: &ProviderInstance,
        host: &HostAddressState,
    ) -> EndpointLookup {
        self.last_problem = None;
        if instance.provider != ProviderKind::RunPod {
            self.note(RunPodProblem::ForeignProvider {
                provider: instance.provider,
            });
            return EndpointLookup::Unknown {
                cause: UncertainCause::AmbiguousResponse,
            };
        }
        let pod = match self.resolve(&instance.instance) {
            Resolved::Pod(pod) => pod,
            Resolved::Gone => return EndpointLookup::Gone,
            Resolved::Unknown(cause) => return EndpointLookup::Unknown { cause },
        };
        let detail = match self.detail(&pod) {
            Ok(detail) => detail,
            Err(cause) => return EndpointLookup::Unknown { cause },
        };
        if !detail.status.exists() {
            return EndpointLookup::Gone;
        }
        if detail.status != PodStatus::Running {
            return EndpointLookup::NotReady {
                status: detail.status,
            };
        }
        match detail.ssh(host) {
            Ok(SshAddress::Public(authority)) => EndpointLookup::Ready { authority },
            Ok(SshAddress::None) => EndpointLookup::NotReady {
                status: detail.status,
            },
            Ok(SshAddress::Refused(refusal)) => EndpointLookup::Refused { refusal },
            Err(problem) => EndpointLookup::Unknown {
                cause: self.unreadable(CommandKind::GetPod, problem),
            },
        }
    }

    /// Puts `key` on the RunPod account unless the account already lists it, then checks
    /// that it does. RunPod installs the account's keys in its pods.
    pub fn install_management_key(&mut self, key: &ManagementPublicKey) -> KeyInstallOutcome {
        self.last_problem = None;
        let line = key.authorized_keys_line();
        let body = parse::key_body(&line).to_owned();
        match self.account_keys() {
            Ok(bodies) if bodies.contains(&body) => return KeyInstallOutcome::AlreadyPresent,
            Ok(_) => {}
            Err(cause) => return KeyInstallOutcome::Unknown { cause },
        }
        match self.call(RunPodCommand::AddSshKey { key: key.clone() }) {
            Ok(_) => {}
            Err(Failure::NothingSent { error } | Failure::Refused { error }) => {
                return KeyInstallOutcome::NotInstalled { error }
            }
            Err(Failure::Uncertain { cause }) => return KeyInstallOutcome::Unknown { cause },
        }
        match self.account_keys() {
            Ok(bodies) if bodies.contains(&body) => KeyInstallOutcome::Installed,
            Ok(_) => {
                self.note(RunPodProblem::KeyNotListed);
                KeyInstallOutcome::Unknown {
                    cause: UncertainCause::AmbiguousResponse,
                }
            }
            Err(cause) => KeyInstallOutcome::Unknown { cause },
        }
    }

    fn account_keys(&mut self) -> Result<Vec<String>, UncertainCause> {
        let stdout = self
            .call(RunPodCommand::ListSshKeys)
            .map_err(Failure::lookup_cause)?;
        parse::account_keys(&stdout)
            .map_err(|problem| self.unreadable(CommandKind::ListSshKeys, problem))
    }
}

impl<P: RunpodctlPort, K: ApiKeySource, C: Clock> RemoteProviderPort for RunPodProvider<P, K, C> {
    fn provision(&mut self, request: &ProvisionRequest) -> ProvisionOutcome {
        self.last_problem = None;
        let invalid = ProvisionOutcome::NotCreated {
            error: ProviderError::InvalidRequest,
        };
        if request.provider != ProviderKind::RunPod {
            self.note(RunPodProblem::ForeignProvider {
                provider: request.provider,
            });
            return invalid;
        }
        if request.kind != OfferingKind::ProviderContainer {
            self.note(RunPodProblem::VmKindRefused { kind: request.kind });
            return invalid;
        }
        let Some(spec) = self.catalog.spec(&request.offering).cloned() else {
            self.note(RunPodProblem::UnknownOffering {
                offering: request.offering.clone(),
            });
            return invalid;
        };
        let name = PodName::for_attempt(&request.attempt);
        // Recorded before sending: absence is believed only a settle window after this.
        self.dispatched.insert(request.attempt, self.clock.now());
        let answer = match self.call(RunPodCommand::CreatePod {
            name: name.clone(),
            spec,
            region: request.region.clone(),
        }) {
            Ok(answer) => answer,
            Err(Failure::NothingSent { error } | Failure::Refused { error }) => {
                return ProvisionOutcome::NotCreated { error }
            }
            Err(Failure::Uncertain { cause }) => return ProvisionOutcome::Unknown { cause },
        };
        let pod = match parse::created_pod(&answer) {
            Ok(pod) => pod,
            Err(problem) => {
                return ProvisionOutcome::Unknown {
                    cause: self.unreadable(CommandKind::CreatePod, problem),
                }
            }
        };
        self.dispatched.insert(request.attempt, self.clock.now());
        self.pods.insert(pod_instance(&pod), pod.clone());
        match self.delivered(&pod, &name, &request.offering) {
            Ok(instance) => ProvisionOutcome::Created { instance },
            Err(cause) => ProvisionOutcome::Unknown { cause },
        }
    }

    fn terminate(&mut self, instance: &ProviderInstance) -> TerminationOutcome {
        self.last_problem = None;
        if instance.provider != ProviderKind::RunPod {
            self.note(RunPodProblem::ForeignProvider {
                provider: instance.provider,
            });
            return TerminationOutcome::Failed {
                error: ProviderError::InvalidRequest,
            };
        }
        let pod = match self.resolve(&instance.instance) {
            Resolved::Pod(pod) => pod,
            Resolved::Gone => return TerminationOutcome::AlreadyGone,
            Resolved::Unknown(cause) => return TerminationOutcome::Unknown { cause },
        };
        let deleted = self.call(RunPodCommand::DeletePod { pod: pod.clone() });
        let remaining = self.still_exists(&pod);
        match (deleted, remaining) {
            (Ok(_), Ok(None)) => TerminationOutcome::Confirmed,
            (Err(_), Ok(None)) => TerminationOutcome::AlreadyGone,
            (Ok(_), Ok(Some(status))) => {
                self.note(RunPodProblem::StillListed { status });
                TerminationOutcome::Unknown {
                    cause: UncertainCause::AmbiguousResponse,
                }
            }
            (Ok(_), Err(cause)) => TerminationOutcome::Unknown { cause },
            (Err(Failure::NothingSent { error } | Failure::Refused { error }), _) => {
                TerminationOutcome::Failed { error }
            }
            (Err(Failure::Uncertain { cause }), _) => TerminationOutcome::Unknown { cause },
        }
    }

    fn find(&mut self, request: &ProvisionRequest) -> LookupOutcome {
        self.last_problem = None;
        if request.provider != ProviderKind::RunPod {
            self.note(RunPodProblem::ForeignProvider {
                provider: request.provider,
            });
            return LookupOutcome::Unknown {
                cause: UncertainCause::AmbiguousResponse,
            };
        }
        let name = PodName::for_attempt(&request.attempt);
        let rows = match self.listing() {
            Ok(rows) => rows,
            Err(cause) => return LookupOutcome::Unknown { cause },
        };
        let mut existing = Vec::new();
        for row in rows {
            if !row
                .name
                .as_deref()
                .is_some_and(|listed| name.carried_by(listed))
            {
                continue;
            }
            match row.status {
                Some(status) if status.exists() => existing.push(row.id),
                Some(_) => {}
                None => {
                    return LookupOutcome::Unknown {
                        cause: self.unreadable(CommandKind::ListPods, ParseProblem::UnknownStatus),
                    }
                }
            }
        }
        match existing.as_slice() {
            [] if self.absence_settled(self.dispatched.get(&request.attempt).copied()) => {
                LookupOutcome::ConfirmedAbsent
            }
            [] => {
                self.note(RunPodProblem::ListingNotSettled);
                LookupOutcome::Unknown {
                    cause: UncertainCause::AmbiguousResponse,
                }
            }
            [pod] => {
                let pod = pod.clone();
                self.pods.insert(pod_instance(&pod), pod.clone());
                match self.delivered(&pod, &name, &request.offering) {
                    Ok(instance) => LookupOutcome::Found { instance },
                    Err(cause) => LookupOutcome::Unknown { cause },
                }
            }
            several => {
                self.note(RunPodProblem::SeveralPods {
                    count: u64::try_from(several.len()).unwrap_or(u64::MAX),
                });
                LookupOutcome::Unknown {
                    cause: UncertainCause::AmbiguousResponse,
                }
            }
        }
    }

    fn final_bill(&mut self, _attempt: &AttemptId) -> BillingReport {
        self.last_problem = None;
        BillingReport::Unavailable
    }
}
