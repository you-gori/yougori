//! The VM service's public API (module docs in `mod.rs`).

use std::fmt;
use std::sync::Arc;

use std::time::{Duration, Instant};

use crate::foundation::coordination::SandboxLifecycle;
use crate::foundation::events::{AuditReceipt, Field, HostFact, Phase};
use crate::foundation::ids::ExecutionId;
use crate::foundation::process::HostProcess;
use crate::sandbox::host::{HostParts, SandboxHost};
use crate::sandbox::integration::{LaunchTable, PortConfig, SinkRefusal};
use crate::sandbox::lifecycle::{PersistedSupervisor, RevocationCause, StateReset};
use crate::sandbox::qemu::QemuBackend;

use super::config::{ConfigRefusal, VmServiceConfig, VmServiceParts};
use super::dto::{
    CommandId, ExecOutcome, ExecRequest, GuestShutdown, GuestShutdownOutcome, LaunchSpec,
    LeaseTerms, RecoverRefusal, RecoveryReport, RevocationReport, RevokeReason, SandboxId,
    SandboxStatus, SharedVm, ShutdownReport, StopReport, MAX_EXEC_DEADLINE,
};
use super::error::{RequestProblem, VmServiceError};
use super::ServiceRuntime;
use super::ports::{ServiceLedger, VmPorts};
use super::state::{join_within, spawn_driver, Core, Hello, Settings, Shared};

/// The sandbox VM service (module docs in `mod.rs`). Every method takes `&self` and may be
/// called from any thread; the service is `Send` and `Sync`. Dropping it shuts it down.
pub struct VmService<P: VmPorts> {
    pub(super) shared: Arc<Shared<P>>,
}

impl<P: VmPorts> VmService<P> {
    /// A service over `parts` with `config`: the QEMU backend over the three host ports and
    /// the ledger's view, the supervisor over the ledger's capacity port, and the sandbox
    /// host over both, the registry, the ledger's resolver and the audit sink. No sandbox
    /// exists yet and no thread runs.
    pub fn new(parts: VmServiceParts<P>, config: VmServiceConfig) -> Result<Self, ConfigRefusal> {
        config.driver.check()?;
        let (host_parts, capacity, session, connector, processes, settings) =
            Self::compose(parts, &config);
        let host = SandboxHost::new(host_parts, session, capacity, config.supervisor);
        Ok(Self {
            shared: Arc::new(Shared::new(Core::new(host, connector, processes, settings))),
        })
    }

    /// A service over `parts` with `config`, recovered from `persisted`, the state an
    /// earlier run stored ([`VmService::persist`]) before the engine restarted (module
    /// docs, route 5): the supervisor restarts over the new backend, which holds no
    /// process, so every stored handle is checked and found gone, no lease or authority
    /// is revived, and what was found is reported. No sandbox of the earlier run is
    /// usable afterwards; its records stay for status and audit. A recovery the
    /// supervisor refuses leaves nothing started. The recovered supervisor issues no lease
    /// (so admits no launch or command) until the caller stored its state and confirmed it
    /// ([`VmService::persist`], then [`VmService::confirm_persisted`]), so a crash before
    /// then recovers the same state again.
    pub fn recover(
        parts: VmServiceParts<P>,
        config: VmServiceConfig,
        persisted: PersistedSupervisor,
    ) -> Result<(Self, RecoveryReport), RecoverRefusal> {
        config.driver.check().map_err(|refusal| RecoverRefusal {
            detail: refusal.to_string(),
        })?;
        let (host_parts, capacity, session, connector, processes, settings) =
            Self::compose(parts, &config);
        let (host, supervisor) =
            SandboxHost::recover(host_parts, persisted, session, capacity, config.supervisor)
                .map_err(|failure| RecoverRefusal {
                    detail: failure.to_string(),
                })?;
        let service = Self {
            shared: Arc::new(Shared::new(Core::new(host, connector, processes, settings))),
        };
        let sandboxes = service.status();
        Ok((
            service,
            RecoveryReport {
                supervisor,
                sandboxes,
            },
        ))
    }

    /// The parts of a service, composed: the QEMU backend over the three host ports and
    /// the ledger's view, the launch table and the host parts over the registry, the
    /// ledger's resolver and the audit sink; the ledger's capacity port for the
    /// supervisor.
    #[allow(clippy::type_complexity)]
    fn compose(
        parts: VmServiceParts<P>,
        config: &VmServiceConfig,
    ) -> (
        HostParts<
            P::Clock,
            super::state::ServiceBackend<P>,
            <P::Ledger as ServiceLedger<P::Clock>>::Resolver,
            P::Segments,
            P::Spool,
            P::Anchor,
        >,
        crate::foundation::coordination::LedgerCapacity<P::Clock, P::Ledger>,
        crate::foundation::evidence::ClockSession,
        P::Connector,
        P::Processes,
        Settings,
    ) {
        let VmServiceParts {
            clock,
            session,
            registry,
            backend,
            qemu,
            host,
            monitor,
            layout,
            ledger,
            sink,
            connector,
            processes,
            transfers,
        } = parts;
        let settings = Settings::new(config, backend.artifact, transfers);
        let backend: P::Backend = QemuBackend::new(backend, qemu, host, monitor, layout, ledger.view()).into();
        let table = LaunchTable::new(PortConfig {
            machine: config.machine,
            state_reset: StateReset::Unsupported {
                detail: "the QEMU profile offers no snapshot or restore".to_owned(),
            },
        });
        let host_parts = HostParts::new(clock, registry, backend, table, ledger.resolver(), sink);
        (
            host_parts,
            ledger.capacity(),
            session,
            connector,
            processes,
            settings,
        )
    }

    /// What to store durably after a call that changed the supervisor's state (a launch, a
    /// command, a stop, a revocation), for [`VmService::recover`] after a restart; then
    /// [`VmService::confirm_persisted`]. `None` once the service shut down.
    pub fn persist(&self) -> Option<PersistedSupervisor> {
        self.shared.lock().host.as_ref().map(|host| host.persist())
    }

    /// The state in `persisted` reached durable storage.
    pub fn confirm_persisted(&self, persisted: &PersistedSupervisor) {
        if let Some(host) = self.shared.lock().host.as_mut() {
            host.confirm_persisted(persisted);
        }
    }

    /// Launches one sandbox and returns once its guest's hello completed the link's
    /// handshake (module docs, route 1). Blocks for the launch transaction (the backend
    /// starts QEMU and observes it), then waits without the lock for the hello: at most the
    /// link's handshake timeout (10 s on the host clock from the challenge).
    pub fn launch(&self, spec: LaunchSpec) -> Result<SandboxId, VmServiceError> {
        self.launch_identified(spec, ExecutionId::generate(), false)
    }

    /// The engine may persist this fresh identity before starting a remote run.
    /// It is not caller-selectable through the public launch DTO. The coordinator
    /// still rejects an identity already used by this service.
    pub(super) fn launch_identified(
        &self,
        spec: LaunchSpec,
        sandbox: ExecutionId,
        remote: bool,
    ) -> Result<SandboxId, VmServiceError> {
        if let Some(image) = &spec.workload_image {
            image
                .validate()
                .map_err(|detail| VmServiceError::InvalidRequest {
                    problem: RequestProblem::WorkloadImage { detail },
                })?;
        }
        if spec.resources.memory_bytes == 0 {
            return Err(VmServiceError::InvalidRequest {
                problem: RequestProblem::NoMemory,
            });
        }
        if spec.resources.cpu_slots == 0 {
            return Err(VmServiceError::InvalidRequest {
                problem: RequestProblem::NoCpuSlots,
            });
        }
        if let Err(refusal) = spec.lease_limits() {
            return Err(VmServiceError::InvalidRequest {
                problem: RequestProblem::LeaseLimit {
                    detail: refusal.to_string(),
                },
            });
        }
        let id = SandboxId::new(sandbox.clone());
        {
            let mut core = self.shared.lock();
            if core.knows(&sandbox) {
                return Err(VmServiceError::RemoteControl {
                    detail: "An execution identity cannot be launched twice.".into(),
                });
            }
            core.begin_launch(&sandbox, &spec)?;
            match spawn_driver(&self.shared, &sandbox) {
                Ok(handle) => {
                    if let Some(boot) = core.boots.get_mut(&sandbox) {
                        boot.driver = Some(handle);
                    }
                }
                Err(error) => {
                    let cleanup = core.abandon(&sandbox, RevocationCause::UserRequested);
                    return Err(VmServiceError::LaunchFailed {
                        sandbox: id,
                        step: super::error::LaunchStep::Driver {
                            detail: error.to_string(),
                        },
                        cleanup,
                    });
                }
            }
        }
        let failed = {
            let mut core = self.shared.lock();
            loop {
                match core.hello(&sandbox) {
                    Hello::Open => {
                        core.mark_ready(&sandbox);
                        // Publish readiness and the extra authority gate under the
                        // SAME lock. No observer can start work between them.
                        if remote {
                            if let Err(error) = core.arm_remote(&id) {
                                break Some(super::error::LaunchStep::Driver {
                                    detail: error.to_string(),
                                });
                            }
                        }
                        break None;
                    }
                    Hello::Failed(step) => break Some(step),
                    Hello::Waiting if core.shutting_down => {
                        break Some(super::error::LaunchStep::ShutDown)
                    }
                    Hello::Waiting => {}
                }
                core.tick_if_due();
                let slice = core.settings.wait_slice;
                core = self.shared.wait(core, slice);
            }
        };
        let Some(step) = failed else {
            return Ok(id);
        };
        let cleanup = self
            .shared
            .lock()
            .abandon(&sandbox, RevocationCause::UserRequested);
        self.join_driver(&sandbox);
        self.shared.notify();
        Err(VmServiceError::LaunchFailed {
            sandbox: id,
            step,
            cleanup,
        })
    }

    /// Runs one command to its end: [`VmService::start_exec`], then
    /// [`VmService::wait_exec`]. Blocks until the command ends: at the latest about one
    /// tick interval after its deadline on the host clock.
    pub fn exec(
        &self,
        sandbox: &SandboxId,
        request: ExecRequest,
    ) -> Result<ExecOutcome, VmServiceError> {
        let command = self.start_exec(sandbox, request)?;
        self.wait_exec(sandbox, command)
    }

    /// Starts one command and returns its id at once, for [`VmService::cancel`] and
    /// [`VmService::wait_exec`] (module docs, route 2). Refused unless the sandbox is
    /// ready, holds authority, finds its VM ready on fresh host evidence and its link is
    /// open.
    pub fn start_exec(
        &self,
        sandbox: &SandboxId,
        request: ExecRequest,
    ) -> Result<CommandId, VmServiceError> {
        if request.deadline.is_zero() || (request.deadline > MAX_EXEC_DEADLINE && request.deadline != Duration::MAX) {
            return Err(VmServiceError::InvalidRequest {
                problem: RequestProblem::deadline(request.deadline, MAX_EXEC_DEADLINE),
            });
        }
        let command = self.shared.lock().start_command(sandbox, request)?;
        self.shared.notify();
        Ok(command)
    }

    /// Waits for `command` to end and takes its outcome; an outcome is taken once. Blocks
    /// without the lock until the command ends.
    pub fn wait_exec(
        &self,
        sandbox: &SandboxId,
        command: CommandId,
    ) -> Result<ExecOutcome, VmServiceError> {
        let mut core = self.shared.lock();
        loop {
            if let Some(outcome) = core.claim(sandbox, command)? {
                return Ok(outcome);
            }
            core.tick_if_due();
            let slice = core.settings.wait_slice;
            core = self.shared.wait(core, slice);
        }
    }

    /// Nonblocking collection for a product-owned background image command. Outcomes
    /// are still consumed exactly once, under the same lock as wait_exec.
    pub fn try_exec_outcome(
        &self,
        sandbox: &SandboxId,
        command: super::CommandId,
    ) -> Result<Option<super::ExecOutcome>, VmServiceError> {
        self.shared.lock().claim(sandbox, command)
    }

    /// Cancels a running command: the host cancels its stream on the link, and its outcome
    /// says it was cancelled by the caller. A command that ended already is left as it
    /// ended. Does not block.
    pub fn cancel(&self, sandbox: &SandboxId, command: CommandId) -> Result<(), VmServiceError> {
        let cancelled = self.shared.lock().cancel_command(sandbox, command);
        self.shared.notify();
        cancelled
    }

    /// Attaches `port` as where `sandbox`'s guest egress streams go (the relay's guest
    /// transport); until a port is attached every guest egress open is refused. Refused
    /// unless the sandbox is ready. Does not block.
    pub fn attach_egress(
        &self,
        sandbox: &SandboxId,
        port: Box<dyn super::egress::EgressPort>,
    ) -> Result<(), VmServiceError> {
        let attached = self.shared.lock().attach_egress(sandbox, port);
        self.shared.notify();
        attached
    }

    /// Attaches the staged workspace at `root` (a folder the engine owns, never the user's
    /// own) to `sandbox`'s file channel as the workspace grant, within `quota`, for at most
    /// `valid_for`; until then every guest file request is refused. Refused unless the
    /// sandbox is ready. Does not block.
    pub fn attach_workspace(
        &self,
        sandbox: &SandboxId,
        root: &std::path::Path,
        uploads: Option<&std::path::Path>,
        quota: crate::sandbox_contract::files::FileQuota,
        valid_for: std::time::Duration,
    ) -> Result<(), VmServiceError> {
        let attached = self
            .shared
            .lock()
            .attach_workspace(sandbox, root, uploads, quota, valid_for);
        self.shared.notify();
        attached
    }

    /// Takes the workspace grant off `sandbox`'s file channel. `false` when none was
    /// attached. Does not block.
    pub fn detach_workspace(&self, sandbox: &SandboxId) -> bool {
        let detached = self.shared.lock().detach_workspace(sandbox);
        self.shared.notify();
        detached
    }

    /// Read-only image inputs, on grant 2. Revocation/stop closes this grant with the
    /// workspace grant; no upload or mutation operation is exposed.
    pub fn attach_image(
        &self,
        sandbox: &SandboxId,
        root: &std::path::Path,
        quota: crate::sandbox_contract::files::FileQuota,
        valid_for: std::time::Duration,
        snapshot: crate::foundation::ids::Digest,
    ) -> Result<(), VmServiceError> {
        let result = self
            .shared
            .lock()
            .attach_image(sandbox, root, quota, valid_for, snapshot);
        self.shared.notify();
        result
    }

    /// Publishes `service` of `sandbox`, declared at its launch, to `audience` for
    /// `lifetime` with a response budget of `budget_bytes` (M14; module docs in `publish`);
    /// returns the publication's number. Refused unless the sandbox is ready. Does not
    /// block.
    pub fn publish(
        &self,
        sandbox: &SandboxId,
        service: &str,
        audience: super::publish::PublicationAudience,
        lifetime: std::time::Duration,
        budget_bytes: u64,
    ) -> Result<(u64, crate::foundation::ids::MonotonicTime), VmServiceError> {
        self.shared
            .lock()
            .publish(sandbox, service, audience, lifetime, budget_bytes)
    }

    /// Withdraws `publication` of `sandbox`: it admits no one more and its sessions close.
    /// Returns how many closed. Does not block.
    pub fn withdraw(&self, sandbox: &SandboxId, publication: u64) -> Result<usize, VmServiceError> {
        self.shared.lock().withdraw(sandbox, publication)
    }

    /// What a proof for `publication` of `sandbox` must be bound to, while it stands.
    pub fn proof_binding(
        &self,
        sandbox: &SandboxId,
        publication: u64,
    ) -> Option<crate::sandbox_contract::connections::ProofBinding> {
        self.shared.lock().proof_binding(sandbox, publication)
    }

    /// Admits a caller of `sandbox`'s `service` presenting `proof` through the connection
    /// gate, joining its stream `outside` to a guest end that opens only for an admitted
    /// caller (M14); returns the session and the guest end's room, for the caller's side to
    /// read no faster than the guest takes. A refused caller learns only that the service
    /// is not published, unless its authentication failed; `outside` is closed then.
    pub fn admit(
        &self,
        sandbox: &SandboxId,
        service: &str,
        proof: Option<crate::sandbox_contract::connections::AuthenticationProof>,
        verifier: &dyn crate::sandbox_contract::connections::ProofVerifier,
        outside: Box<dyn crate::sandbox_contract::connections::SessionStream>,
        caller_room: Option<super::ingress::CallerRoom>,
    ) -> Result<
        (u64, super::ingress::GuestIngressWatch),
        crate::sandbox_contract::connections::GateRefusal,
    > {
        let admitted =
            self.shared
                .lock()
                .admit(sandbox, service, proof, verifier, outside, caller_room);
        self.shared.notify();
        admitted
    }

    /// Grants `caller`'s connection endpoint `endpoint`, declared at its launch, the service
    /// `service` `callee`'s launch declared, for `lifetime`, each connection carrying at most
    /// `budget_bytes` each way (M14; module docs in `connect`): the gate records the caller's
    /// and the callee's copy of the grant. Returns when it expires. Refused unless both are
    /// ready. Does not block.
    pub fn connect(
        &self,
        caller: &SandboxId,
        endpoint: &str,
        callee: &SandboxId,
        service: &str,
        lifetime: std::time::Duration,
        budget_bytes: u64,
    ) -> Result<crate::foundation::ids::MonotonicTime, VmServiceError> {
        self.shared.lock().connect_sandboxes(
            caller,
            endpoint,
            callee,
            service,
            lifetime,
            budget_bytes,
        )
    }

    /// Withdraws what `caller`'s endpoint `endpoint` is granted: both copies of the grant go
    /// and its open connections close. Returns how many closed. Does not block.
    pub fn disconnect(&self, caller: &SandboxId, endpoint: &str) -> Result<usize, VmServiceError> {
        let closed = self.shared.lock().disconnect(caller, endpoint);
        self.shared.notify();
        closed
    }

    /// The private directory of `sandbox`'s boot (its sockets and the link's secret), while
    /// the service holds one.
    pub fn private_directory(&self, sandbox: &SandboxId) -> Option<String> {
        self.shared.lock().private_directory(sandbox)
    }

    /// `sandbox`'s connection endpoints and what each is granted, the grants other
    /// sandboxes hold to its services, and its open and refused connections.
    pub fn connections(&self, sandbox: &SandboxId) -> super::connect::ConnectionsView {
        self.shared.lock().connections_view(sandbox)
    }

    /// Pumps every open session and sandbox connection once: a caller's bytes toward the
    /// guest, the guest's answers, charged first, toward the caller. The caller of this
    /// loops it.
    pub fn pump_sessions(&self) -> super::publish::SessionsPumped {
        let pumped = self.shared.lock().pump_sessions();
        self.shared.notify();
        pumped
    }

    /// `sandbox`'s declared services and its publications.
    pub fn publications(&self, sandbox: &SandboxId) -> super::publish::PublicationsView {
        self.shared.lock().publications_view(sandbox)
    }

    /// The guest end of one caller's stream to `sandbox`'s guest `listener` (`port-N`, the
    /// guest service on its own port N), for the connection gate (M14; module docs in
    /// `ingress`): it opens on the link once the gate first uses it, so a caller the gate
    /// refuses never reaches the guest. Refused unless the sandbox is ready. Does not block.
    pub fn ingress(
        &self,
        sandbox: &SandboxId,
        listener: &str,
    ) -> Result<super::ingress::GuestIngress, VmServiceError> {
        let listener = crate::sandbox::link::LinkName::new(listener).map_err(|error| {
            VmServiceError::Ingress {
                detail: format!("{listener} is not a listener name: {error:?}"),
            }
        })?;
        let handle = self.shared.lock().ingress(sandbox, listener);
        self.shared.notify();
        handle
    }

    /// Detaches `sandbox`'s egress port: opens are refused again and every open egress
    /// stream is cancelled. `false` when none was attached. Does not block.
    pub fn detach_egress(&self, sandbox: &SandboxId) -> Result<bool, VmServiceError> {
        let detached = self.shared.lock().detach_egress(sandbox);
        self.shared.notify();
        detached
    }

    /// Stops the sandbox (module docs, route 3): the guest is asked to shut down within the
    /// configured grace, the host observes whether it went (its stream ended or its
    /// process ended) within that grace in real time, then the sandbox is revoked as
    /// user-requested, which stops a VM still running through its handle; reported as the
    /// stop's milestones. Blocks for up to the grace, then for the revocation, the VM's
    /// stop (the host port's bounded termination) and the observations, then up to the
    /// join bound for the boot's driver to end.
    pub fn stop(&self, sandbox: &SandboxId) -> Result<StopReport, VmServiceError> {
        let (requested_at, requested) = {
            let mut core = self.shared.lock();
            if core.shutting_down {
                return Err(VmServiceError::ShuttingDown);
            }
            if !core.knows(sandbox.execution()) {
                return Err(VmServiceError::UnknownSandbox {
                    sandbox: sandbox.clone(),
                });
            }
            let requested_at = core.now().ok_or(VmServiceError::ShuttingDown)?;
            let requested = core.request_guest_shutdown(sandbox.execution());
            (requested_at, requested)
        };
        self.shared.notify();
        let guest_shutdown = match requested {
            Ok((at, grace_seconds)) => {
                let outcome = self.await_guest_gone(sandbox.execution());
                GuestShutdown::Requested {
                    at,
                    grace_seconds,
                    outcome,
                }
            }
            Err(reason) => GuestShutdown::NotRequested { reason },
        };
        let report = {
            let mut core = self.shared.lock();
            if core.shutting_down {
                return Err(VmServiceError::ShuttingDown);
            }
            let ended = core.end(sandbox.execution(), RevocationCause::UserRequested)?;
            StopReport {
                sandbox: sandbox.clone(),
                requested_at,
                guest_shutdown,
                vm_stop: ended.vm_stop,
                directory: ended.directory,
                commands_ended: ended.commands_ended,
            }
        };
        self.join_driver(sandbox.execution());
        self.shared.notify();
        Ok(report)
    }

    /// Waits, in real time and without the lock, up to the shutdown grace for the host to
    /// observe `sandbox`'s guest gone after a shutdown request.
    fn await_guest_gone(&self, sandbox: &ExecutionId) -> GuestShutdownOutcome {
        let started = Instant::now();
        let mut core = self.shared.lock();
        let grace = core.settings.shutdown_grace;
        loop {
            if let Some(outcome) = core.guest_gone(sandbox) {
                return outcome;
            }
            if started.elapsed() >= grace || core.shutting_down {
                return GuestShutdownOutcome::GraceExpired {
                    waited_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
                };
            }
            core.tick_if_due();
            let slice = core.settings.wait_slice;
            core = self.shared.wait(core, slice);
        }
    }

    /// Revokes the sandbox for `reason` (module docs, route 3): new work denied, channels
    /// closed, VM stopped and cleanup done, each its own observed result with its time.
    /// Blocks as [`VmService::stop`] does. Revoking again changes nothing and reports
    /// where the revocation stands.
    pub fn revoke(
        &self,
        sandbox: &SandboxId,
        reason: RevokeReason,
    ) -> Result<RevocationReport, VmServiceError> {
        let report = {
            let mut core = self.shared.lock();
            if core.shutting_down {
                return Err(VmServiceError::ShuttingDown);
            }
            if !core.knows(sandbox.execution()) {
                return Err(VmServiceError::UnknownSandbox {
                    sandbox: sandbox.clone(),
                });
            }
            let ended = core.end(sandbox.execution(), reason.cause())?;
            core.revocation_report(sandbox, reason, ended)
        };
        self.join_driver(sandbox.execution());
        self.shared.notify();
        Ok(report)
    }

    /// Revokes `sandbox` for `cause` after its VM ended under the lifetime supervisor
    /// (VM-W26): its engine was counted as failed (`EngineDied`, VM-D7) or a lease limit
    /// passed by its grace (`LeaseExpired`). The service then observes the VM's end itself,
    /// as for a VM that stopped on its own, and its revocation names why.
    pub fn revoke_ended(
        &self,
        sandbox: &SandboxId,
        cause: RevocationCause,
    ) -> Result<(), VmServiceError> {
        {
            let mut core = self.shared.lock();
            if core.shutting_down {
                return Err(VmServiceError::ShuttingDown);
            }
            if !core.knows(sandbox.execution()) {
                return Err(VmServiceError::UnknownSandbox {
                    sandbox: sandbox.clone(),
                });
            }
            core.end(sandbox.execution(), cause)?;
        }
        self.join_driver(sandbox.execution());
        self.shared.notify();
        Ok(())
    }

    /// Every sandbox the supervisor knows, in the order of their ids. Does not block
    /// beyond the lock; empty once the service shut down.
    pub fn status(&self) -> Vec<SandboxStatus> {
        self.shared.lock().statuses()
    }

    /// Fresh read-only observation of this VM's actual backend. A remote management
    /// bridge may use it before delegation; it issues no workload authority.
    pub fn observe_vm(&self, sandbox: &SandboxId) -> Result<super::SandboxStatus, VmServiceError> {
        let mut core = self.shared.lock();
        core.ready_boot(sandbox)?;
        let host = core.host.as_mut().ok_or(VmServiceError::ShuttingDown)?;
        let observed = host
            .with_supervisor(|supervisor, backend, _| {
                supervisor.observe_readiness(sandbox.execution(), backend)
            })
            .map_err(|error| VmServiceError::RemoteControl {
                detail: error.to_string(),
            })?;
        if !matches!(
            observed,
            crate::sandbox::lifecycle::ObservedReadiness::Ready { .. }
        ) {
            return Err(VmServiceError::RemoteControl {
                detail: "The host could not freshly observe this VM ready.".into(),
            });
        }
        core.absorb_log();
        core.statuses()
            .into_iter()
            .find(|status| &status.sandbox == sandbox)
            .ok_or_else(|| VmServiceError::UnknownSandbox {
                sandbox: sandbox.clone(),
            })
    }

    /// Duplicates the job and process handles of `sandbox`'s VM into `holder` (VM-W26: the
    /// lifetime supervisor holds every VM beside the service, so a VM's end does not wait
    /// for this service's process); the service keeps its own handles. Refused for a
    /// sandbox without a VM the backend holds.
    pub fn share_vm(&self, sandbox: &SandboxId, holder: &HostProcess) -> Result<SharedVm, String> {
        let core = self.shared.lock();
        let host = core
            .host
            .as_ref()
            .ok_or("the sandbox service has shut down")?;
        let record = host
            .supervisor()
            .sandbox(sandbox.execution())
            .ok_or_else(|| format!("there is no sandbox {sandbox}"))?;
        let vm = host
            .supervisor()
            .coordinator()
            .sandbox(sandbox.execution())
            .and_then(SandboxLifecycle::vm)
            .ok_or_else(|| format!("the sandbox {sandbox} has no VM"))?;
        let process = host
            .backend()
            .process_of(&vm)
            .ok_or_else(|| format!("the backend holds no process for the VM of {sandbox}"))?;
        let handles = host.backend().share_process(&process, holder)?;
        Ok(SharedVm {
            sandbox: sandbox.clone(),
            process,
            class: record.class,
            handles,
        })
    }

    /// What is left now of each sandbox's lease limits, on the supervisor's clock (§6.2),
    /// for the lifetime supervisor's backstop (VM-W26). Read from a copy of each lease, so
    /// reading changes nothing. Empty once the service shut down.
    pub fn lease_terms(&self) -> Vec<LeaseTerms> {
        let core = self.shared.lock();
        let Some(host) = core.host.as_ref() else {
            return Vec::new();
        };
        let supervisor = host.supervisor();
        // Read the same-host anchor FIRST: time between the two clock reads must
        // shorten the delegated lifetime, never extend it. Process-relative
        // MonotonicTime cannot itself be sent to another process as a deadline.
        let host_ns = crate::foundation::elapsed_clock::nanos();
        let now = supervisor.now();
        supervisor
            .sandboxes()
            .map(|record| {
                let limits = *record.lease.limits();
                let left = record.lease.clone().check(now).ok();
                let delegated_left = core
                    .boots
                    .get(&record.identity.execution)
                    .and_then(|boot| boot.remote.as_ref())
                    .map(|remote| remote.remaining(now));
                LeaseTerms {
                    sandbox: SandboxId::new(record.identity.execution.clone()),
                    class: record.class,
                    idle_left: left.map_or(Duration::ZERO, |left| left.idle),
                    absolute_left: limits
                        .absolute
                        .map(|_| left.and_then(|left| left.absolute).unwrap_or_default()),
                    renewal_left: super::remote::earliest(
                        limits.service_renewal.map(|_| {
                            left.and_then(|left| left.service_renewal)
                                .unwrap_or_default()
                        }),
                        delegated_left,
                    ),
                    delegation_deadline_host_ns: delegated_left.map(|left| {
                        u64::try_from(left.as_nanos())
                            .ok()
                            .and_then(|left| host_ns.checked_add(left))
                            .unwrap_or(0)
                    }),
                }
            })
            .collect()
    }

    /// The service's evidence clock now: the session and time its launch records and
    /// observations are stamped on, so a judge of them reads them on the same clock (the
    /// host evidence inventory keeps a clock of its own). `None` once the service shut down.
    pub fn clock_reading(&self) -> Option<crate::foundation::evidence::ClockReading> {
        self.shared
            .lock()
            .host
            .as_ref()
            .map(|host| host.registry().now())
    }

    /// The latest launches the backend refused in this run, oldest first (at most 32), each
    /// with its typed refusal: a controlled negative launch reads its own here.
    pub fn refused_launches(&self) -> Vec<crate::sandbox::integration::RefusedLaunch> {
        let mut core = self.shared.lock();
        core.absorb_log();
        core.refused.iter().cloned().collect()
    }

    /// The launch records the backend sealed in this run, oldest first: the doctor reads
    /// the host-observed facts of each as boundary check results (M08).
    pub fn launch_records(&self) -> Vec<crate::sandbox::backend::LaunchRecord> {
        let core = self.shared.lock();
        let mut records: Vec<_> = core
            .host
            .as_ref()
            .map(|host| host.table().records().cloned().collect())
            .unwrap_or_default();
        records.sort_by_key(|record| record.recorded_at());
        records
    }

    /// Each sandbox the supervisor knows, with its authority now (the CORE-04 rule of
    /// `foundation::transfer::CoordinatorAuthority`), for a port that must answer without
    /// this service's lock, such as the transfer gate of the guest's file bodies, which
    /// runs inside it. Empty once the service shut down.
    pub fn authorities(&self) -> Vec<(ExecutionId, crate::foundation::transfer::ParentStatus)> {
        let core = self.shared.lock();
        let Some(host) = core.host.as_ref() else {
            return Vec::new();
        };
        let supervisor = host.supervisor();
        supervisor
            .sandboxes()
            .map(|record| {
                let execution = record.identity.execution.clone();
                let status = crate::foundation::transfer::parent_status_in(
                    supervisor.coordinator(),
                    &execution,
                );
                (execution, status)
            })
            .collect()
    }

    /// Gives the durable audit stream a host fact the engine's response path drafted about
    /// `sandbox` (a monitoring signal, a response decision), in the sandbox's running
    /// context: the receipt or the sink's refusal; the outer error once the service shut
    /// down.
    pub fn record_running_fact(
        &self,
        sandbox: &SandboxId,
        fact: HostFact,
        fields: Vec<Field>,
    ) -> Result<Result<AuditReceipt, SinkRefusal>, VmServiceError> {
        let mut core = self.shared.lock();
        let host = core.host.as_mut().ok_or(VmServiceError::ShuttingDown)?;
        Ok(host.record_running_fact(sandbox.execution(), fact, fields))
    }

    /// Gives the durable audit stream a host fact about `sandbox` at `phase`, such as a
    /// promotion of its files after it stopped or after a restart of the engine (the
    /// record's own fields name the sandbox; the stream's context of it may be gone).
    pub fn record_fact(
        &self,
        sandbox: &SandboxId,
        phase: Phase,
        fact: HostFact,
        fields: Vec<Field>,
    ) -> Result<Result<AuditReceipt, SinkRefusal>, VmServiceError> {
        let mut core = self.shared.lock();
        let host = core.host.as_mut().ok_or(VmServiceError::ShuttingDown)?;
        Ok(host.record_fact(sandbox.execution(), phase, fact, fields))
    }

    /// Shuts the service down: no call is taken any more, every driver is asked to stop and
    /// joined within the join bound, every channel is closed through the host's shutdown
    /// with its close frame written to the stream, and waiting calls return. VMs are not
    /// stopped: stop or revoke them first. A second call returns an empty report.
    pub fn shutdown(&self) -> ShutdownReport {
        let Some(handles) = self.shared.lock().begin_shutdown() else {
            return ShutdownReport::default();
        };
        self.shared.notify();
        let bound = self.shared.lock().settings.join_bound;
        let (drivers_joined, left) = join_within(handles, bound);
        let mut report = self.shared.lock().close_all(bound);
        report.drivers_joined = drivers_joined;
        report.drivers_not_joined = left
            .into_iter()
            .map(|(sandbox, _)| SandboxId::new(sandbox))
            .collect();
        self.shared.notify();
        report
    }

    /// Joins `sandbox`'s driver within the join bound, without the lock; a driver that has
    /// not ended by then is kept for the shutdown.
    fn join_driver(&self, sandbox: &ExecutionId) {
        let (handle, bound) = {
            let mut core = self.shared.lock();
            (core.take_driver(sandbox), core.settings.join_bound)
        };
        let Some(handle) = handle else {
            return;
        };
        let (_, left) = join_within(vec![(sandbox.clone(), handle)], bound);
        for (sandbox, handle) in left {
            self.shared.lock().put_driver(&sandbox, handle);
        }
    }
}

impl<P: VmPorts> Drop for VmService<P> {
    fn drop(&mut self) {
        self.shutdown();
    }
}

impl<P: VmPorts> fmt::Debug for VmService<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let core = self.shared.lock();
        let sandboxes: Vec<(&ExecutionId, _)> = core
            .boots
            .iter()
            .map(|(execution, boot)| (execution, boot.phase))
            .collect();
        f.debug_struct("VmService")
            .field("sandboxes", &sandboxes)
            .field("shutting_down", &core.shutting_down)
            .finish_non_exhaustive()
    }
}
