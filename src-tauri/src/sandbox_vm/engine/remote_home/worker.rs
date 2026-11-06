use super::*;
use crate::foundation::coordination::LeaseTerms;
use crate::foundation::evidence::{ProviderKind, RuntimeRequirement};
use crate::foundation::ids::OperationId;
use crate::sandbox::vm_service::VmDelegation;
use crate::sandbox_contract::effects::AccountRef;
use crate::sandbox_contract::files::{
    ClockSkewPolicy, RemoteExpiry, RemoteObservation, WallClockGuard,
};
use crate::sandbox_contract::remote::{
    AdapterConfig, AttemptId, CredentialPlacement, EnrollmentPolicy, HostAuthority,
    ManagementAction, ManagementIdentity, OfferingShape, ProgramPath, RemoteAccountName,
    RemoteOffering, RemoteRequest, RemoteShellKind, RemoteVmAdapter,
};
use crate::sandbox_contract::remote_ssh::{
    confirmed_creation_cancelled, confirmed_remote_end, owner_identity_file,
    parse_owner_public_key, ControlAgent, ControlLimits, ControlTransport, EngineManagement,
    EnrolledHostKey, IdentityFile, KnownHostsFile, ManagementChannel, ProcessSshPort, SshFilePath,
    SshLimits,
};

fn ssh_program() -> Result<PathBuf, String> {
    #[cfg(windows)]
    let path = std::env::var_os("SystemRoot")
        .map(PathBuf::from)
        .ok_or("Windows directory unavailable")?
        .join("System32/OpenSSH/ssh.exe");
    #[cfg(not(windows))]
    let path = PathBuf::from("/usr/bin/ssh");
    if !path.is_file() {
        return Err("Install the system OpenSSH client before using remote VMs.".into());
    }
    Ok(path)
}
fn ssh_path(path: &Path) -> Result<SshFilePath, String> {
    SshFilePath::new(
        path.to_str()
            .ok_or("SSH path is not UTF-8")?
            .replace('\\', "/"),
    )
    .map_err(|e| e.to_string())
}
fn limits(seconds: u64) -> Result<SshLimits, String> {
    SshLimits::new(
        seconds.min(10) as u32,
        2,
        2,
        Duration::from_secs(seconds),
        2 * 1024 * 1024,
        64 * 1024,
    )
    .map_err(|e| e.to_string())
}

/// Reject unusable local inputs before creating a remote cleanup obligation.
pub(super) fn preflight(profile: &SshProfile) -> Result<(), String> {
    ssh_program()?;
    owner_identity_file(ssh_path(Path::new(&profile.identity_file))?)?;
    parse_owner_public_key(profile.host_key.as_bytes())?;
    Ok(())
}

struct Session {
    adapter: RemoteVmAdapter<SystemClock>,
    authority: VmDelegation<ProductionPorts>,
    host: Arc<trust::Host>,
    identity: ManagementIdentity,
    program: PathBuf,
    directory: PathBuf,
    known: KnownHostsFile,
    key: IdentityFile,
    bootstrap: EngineManagement<ProcessSshPort>,
    active: EngineManagement<ProcessSshPort>,
    cleanup: EngineManagement<ProcessSshPort>,
    wall: WallClockGuard,
}
impl Session {
    fn prepare(
        manager: &Manager,
        p: &Production,
        run: &Run,
        cleanup: bool,
    ) -> Result<Self, String> {
        let profile = if cleanup {
            run.cleanup_profile()
        } else {
            &run.profile
        };
        let host = manager.host(profile, None, p.clock.now(), cleanup)?;
        if !cleanup {
            host.check_new()?
        }
        let (instance, target) = trust::target(profile)?;
        if instance.host() != run.host {
            return Err("Saved remote host identity changed.".into());
        }
        let public = parse_owner_public_key(profile.host_key.as_bytes())?;
        let key = owner_identity_file(ssh_path(Path::new(&profile.identity_file))?)?;
        let enrollment = host
            .known
            .verify(&run.host, &public.key)
            .map_err(|e| e.to_string())?;
        let identity = ManagementIdentity::new(
            enrollment,
            RemoteAccountName::new(&profile.username).map_err(|e| e.to_string())?,
            key.credential(),
            RemoteShellKind::Posix,
            BTreeSet::from([
                ManagementAction::LaunchVm,
                ManagementAction::SuperviseVm,
                ManagementAction::CollectLogs,
                ManagementAction::TerminateVm,
            ]),
        )
        .map_err(|e| e.to_string())?;
        let offering = RemoteOffering {
            provider: ProviderKind::ExistingSsh,
            region: instance.region.clone(),
            offering: instance.offering.clone(),
            kind: instance.kind,
            account: AccountRef::new(digest(
                "yougori/remote-home/owner-account/v1",
                &[profile.username.as_bytes(), instance.instance.as_bytes()],
            )),
            price: None,
            shape: OfferingShape {
                vcpus: 1,
                memory_bytes: run.memory_mib * MIB_BYTES,
                gpus: 0,
            },
        };
        let config = AdapterConfig {
            terms: LeaseTerms {
                term: Duration::from_secs(30),
                max_lifetime: Duration::from_secs(run.lifetime_seconds),
                cancel_within: Duration::from_secs(30),
            },
            max_control_silence: Duration::from_secs(10),
            skew: ClockSkewPolicy {
                max_skew_seconds: 1,
                max_remote_lifetime_seconds: 60,
            },
            termination_allowance_seconds: 60,
            escalate_after_attempts: 3,
            enrollment: EnrollmentPolicy::default(),
            confidential: None,
        };
        let mut adapter = RemoteVmAdapter::plan(
            p.clock.clone(),
            AttemptId::new(run.run),
            run.parent.execution().clone(),
            &RemoteRequest {
                requirement: RuntimeRequirement::VmSandbox,
                credentials: CredentialPlacement::Home,
                gpus: 0,
            },
            &[offering],
            config,
        )
        .map_err(|e| e.to_string())?;
        adapter
            .attach_existing(instance)
            .map_err(|e| e.to_string())?;
        adapter
            .adopt_enrollment(&host.known, &public.key)
            .map_err(|e| e.to_string())?;
        let authority = if cleanup {
            p.service.cleanup_delegation(&run.parent, run.parent_boot)
        } else {
            p.service.delegation(&run.parent)
        }
        .map_err(|e| e.to_string())?;
        if authority.parent_boot() != run.parent_boot {
            return Err("Parent VM boot changed; old remote authority cannot resume.".into());
        }
        // Fresh directory, only public known_hosts is written here. No key copying.
        let directory = manager
            .root
            .join("ssh")
            .join(uuid::Uuid::new_v4().to_string());
        fs::create_dir_all(&directory).map_err(|e| e.to_string())?;
        let enrolled =
            EnrolledHostKey::new(&host.known, target, public.key.algorithm(), public.blob)
                .map_err(|e| e.to_string())?;
        let known = KnownHostsFile::write(enrolled, ssh_path(&directory.join("known_hosts"))?)
            .map_err(|e| e.to_string())?;
        let program = ssh_program()?;
        let client = |seconds| -> Result<EngineManagement<ProcessSshPort>, String> {
            let port = ProcessSshPort::new(&program, &directory).map_err(|e| e.to_string())?;
            EngineManagement::new(
                ManagementChannel::new(port, known.clone(), key.clone(), limits(seconds)?),
                ProgramPath::new(&run.program).map_err(|e| e.to_string())?,
                run.endpoint.clone(),
                run.engine_sha256,
            )
        };
        Ok(Self {
            bootstrap: client(120)?,
            active: client(3)?,
            cleanup: client(30)?,
            adapter,
            authority,
            host,
            identity,
            program,
            directory,
            known,
            key,
            wall: WallClockGuard::default(),
        })
    }

    fn acknowledge(&mut self, expiry: &RemoteExpiry) -> Result<(), String> {
        let sent_at = self
            .adapter
            .last_grant()
            .ok_or("No control grant to acknowledge")?
            .0;
        let observation = RemoteObservation {
            sent_at,
            received_at: self.authority.now(),
            local_unix_seconds: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|_| "Home wall clock predates the epoch")?
                .as_secs()
                .try_into()
                .map_err(|_| "Home wall clock overflow")?,
        };
        self.adapter
            .observe_remote_expiry(expiry, &observation, &mut self.wall, &mut self.authority)
            .map(|_| ())
            .map_err(|e| e.to_string())
    }

    fn serve(
        &mut self,
        manager: &Manager,
        p: &Production,
        entry: &Entry,
        receiver: &mpsc::Receiver<Work>,
    ) -> Result<(), String> {
        let run = entry.snapshot();
        if p.shutdown.is_cancelled() || entry.stop.load(Ordering::Acquire) {
            return Ok(());
        }
        let result = self.bootstrap.call(
            &mut self.adapter,
            &mut self.authority,
            &self.host.known,
            &self.identity,
            &RemoteManagementRequest::Launch {
                run: run.run,
                memory_mib: run.memory_mib,
                lifetime_seconds: run.lifetime_seconds,
            },
        );
        self.host.persist()?;
        let result = result?;
        if result["state"] != "ready" {
            return Err(
                "Remote creation did not produce a ready VM; cleanup is being reconciled.".into(),
            );
        }
        let observation: RemoteVmObservation =
            serde_json::from_value(result["observation"].clone())
                .map_err(|_| "Invalid remote VM observation")?;
        manager.update(entry, |r| r.observation = Some(observation.clone()))?;
        if p.shutdown.is_cancelled() || entry.stop.load(Ordering::Acquire) {
            return Ok(());
        }
        let evidence = self.active.probe_runtime(
            &mut self.adapter,
            &mut self.authority,
            &self.host.known,
            &self.identity,
            &observation.binding,
            p.clock.clone(),
        );
        self.host.persist()?;
        let (fresh, offer, evidence) = evidence?;
        if fresh != observation {
            return Err("Remote identity changed during admission.".into());
        }
        self.adapter
            .confirm_runtime(&offer, Some(&evidence))
            .map_err(|e| e.to_string())?;
        let agent = ControlAgent::for_engine(
            ProgramPath::new(&run.program).map_err(|e| e.to_string())?,
            &run.endpoint,
            &observation.binding.execution,
        )
        .map_err(|e| e.to_string())?;
        let invocation = agent
            .invocation(&self.identity, &self.host.known)
            .map_err(|e| e.to_string())?;
        let control_limits =
            ControlLimits::new(limits(3)?, Duration::from_secs(10), Duration::from_secs(1))
                .map_err(|e| e.to_string())?;
        let mut control = ControlTransport::new(
            &self.program,
            &self.directory,
            self.known.clone(),
            self.key.clone(),
            control_limits,
            &invocation,
        )
        .map_err(|e| e.to_string())?;
        let result = (|| -> Result<(), String> {
            control
                .open(
                    &mut self.adapter,
                    &mut self.authority,
                    &self.host.known,
                    &self.identity,
                )
                .map_err(|e| e.to_string())?;
            control
                .launch(
                    &mut self.adapter,
                    &mut self.authority,
                    &self.host.known,
                    OperationId::new(format!("remote-{}", run.run.to_hex()))
                        .map_err(|e| e.to_string())?,
                    None,
                )
                .map_err(|e| e.to_string())?;
            p.checkpoint()?;
            self.host.persist()?;
            // Ask the pinned engine for its real applied child lease. An initial
            // heartbeat alone only acknowledges the channel, not a work grant.
            let deadline = Instant::now() + Duration::from_secs(5);
            let mut acknowledged = false;
            while Instant::now() < deadline && !acknowledged {
                self.adapter
                    .check_authority(&mut self.authority)
                    .map_err(|e| e.to_string())?;
                control
                    .receive(
                        &mut self.adapter,
                        &mut self.authority,
                        &self.host.known,
                        Duration::from_millis(100),
                    )
                    .map_err(|e| e.to_string())?;
                let reply = self.active.call(
                    &mut self.adapter,
                    &mut self.authority,
                    &self.host.known,
                    &self.identity,
                    &RemoteManagementRequest::Probe {
                        binding: observation.binding.clone(),
                    },
                )?;
                let view = &reply["control"];
                acknowledged = view["connected"] == true
                    && view["closed"] == false
                    && serde_json::from_value::<crate::foundation::ids::LeaseId>(
                        view["lease"].clone(),
                    )
                    .is_ok()
                    && view["remaining_ms"].as_u64().is_some_and(|ms| ms > 0);
            }
            if !acknowledged {
                return Err("Remote VM did not acknowledge its initial authority grant.".into());
            }
            manager.update(entry, |r| {
                r.phase = Phase::Ready;
                r.detail = None
            })?;
            loop {
                if p.shutdown.is_cancelled() || entry.stop.load(Ordering::Acquire) {
                    break;
                }
                self.host.check_new()?;
                self.adapter
                    .check_authority(&mut self.authority)
                    .map_err(|e| e.to_string())?;
                let heard = control.receive(
                    &mut self.adapter,
                    &mut self.authority,
                    &self.host.known,
                    Duration::from_millis(100),
                );
                self.host.persist()?;
                match heard.map_err(|e| e.to_string())? {
                    Some(crate::sandbox_contract::remote::FrameOutcome::StatusReported {
                        expiry,
                    }) => self.acknowledge(&expiry)?,
                    Some(crate::sandbox_contract::remote::FrameOutcome::Renewed { .. }) => {
                        p.checkpoint()?
                    }
                    _ => {}
                }
                if let Ok(work) = receiver.try_recv() {
                    let result = if Instant::now() > work.expires {
                        Err("The queued request expired without running.".into())
                    } else if entry.stop.load(Ordering::Acquire) || p.shutdown.is_cancelled() {
                        Err("Remote work stopped before this request ran.".into())
                    } else {
                        self.active.call(
                            &mut self.adapter,
                            &mut self.authority,
                            &self.host.known,
                            &self.identity,
                            &work.request,
                        )
                    };
                    let persisted = self.host.persist();
                    let uncertain = result.is_err();
                    let _ = work.reply.send(result);
                    persisted?;
                    if uncertain {
                        return Err("Remote management outcome is uncertain; work stopped and cleanup is being reconciled.".into());
                    }
                }
            }
            Ok(())
        })();
        // Termination releases the real home child lease before slow cleanup.
        let _ = self.adapter.begin_termination(&mut self.authority);
        control.close(&mut self.adapter, &mut self.authority, &self.host.known);
        p.checkpoint()?;
        self.host.persist()?;
        result
    }

    fn reconcile(&mut self, manager: &Manager, entry: &Entry) -> Result<(), String> {
        let run = entry.snapshot();
        self.adapter
            .begin_termination(&mut self.authority)
            .map_err(|e| e.to_string())?;
        manager.update(entry, |r| r.phase = Phase::Stopping)?;
        let result = self.cleanup.call(
            &mut self.adapter,
            &mut self.authority,
            &self.host.known,
            &self.identity,
            &RemoteManagementRequest::Reconcile { run: run.run },
        );
        self.host.persist()?;
        let receipt = result?;
        let phase = if confirmed_creation_cancelled(run.run, &receipt) {
            if run.observation.is_some() {
                return Err("Creation-cancelled receipt contradicts the observed VM.".into());
            }
            Phase::CreationCancelled
        } else {
            confirmed_remote_end(run.run, run.observation.as_ref(), &receipt)?;
            if self.adapter.runtime().is_some() {
                let identity = self
                    .adapter
                    .identity()
                    .ok_or("Missing remote enrollment")?
                    .clone();
                let workload = run
                    .observation
                    .as_ref()
                    .ok_or("Missing remote observation")?
                    .binding
                    .workload_identity();
                self.adapter
                    .confirm_attached_workload_stopped(&identity, workload)
                    .map_err(|e| e.to_string())?;
            }
            // Restart cleanup has no admitted runtime or work lease. The exact
            // durable intent is closed, without inventing a fresh RuntimeOffer.
            Phase::Ended
        };
        manager.update(entry, |r| {
            r.phase = phase;
            r.receipt = Some(receipt)
        })
    }
}
impl Drop for Session {
    fn drop(&mut self) {
        // Only the public pin file and empty directory created by this session.
        let _ = fs::remove_file(self.directory.join("known_hosts"));
        let _ = fs::remove_dir(&self.directory);
    }
}

impl Manager {
    pub(in crate::sandbox_vm::engine) fn recover(self: &Arc<Self>, p: Arc<Production>) {
        let entries = self
            .runs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .cloned()
            .collect::<Vec<_>>();
        for entry in entries {
            if !entry.snapshot().phase.terminal() {
                let _ = self.spawn(p.clone(), entry, true);
            }
        }
    }
    pub(super) fn spawn(
        self: &Arc<Self>,
        p: Arc<Production>,
        entry: Arc<Entry>,
        cleanup: bool,
    ) -> Result<(), String> {
        // Serialize the transition to an active holder with explicit host-key
        // replacement. A planned-but-not-started worker must not slip past it.
        let admission = self.runs.lock().map_err(|_| "Remote lock unavailable")?;
        let snapshot = entry.snapshot();
        if snapshot.phase.terminal()
            || !admission.get(&snapshot.run).is_some_and(|current| Arc::ptr_eq(current, &entry))
        {
            return Ok(());
        }
        if entry
            .finished
            .compare_exchange(true, false, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Ok(());
        }
        drop(admission);
        let (sender, receiver) = mpsc::sync_channel(8);
        *entry
            .sender
            .lock()
            .map_err(|_| "Remote sender lock unavailable")? = Some(sender);
        let manager = self.clone();
        let owned = entry.clone();
        let result=std::thread::Builder::new().name("remote-vm".into()).spawn(move || {
            let result=std::panic::catch_unwind(std::panic::AssertUnwindSafe(||->Result<(),String> {
                let run=owned.snapshot();
                let mut session=match Session::prepare(&manager,&p,&run,cleanup) {
                    Ok(session)=>session,
                    Err(error) if !cleanup=>{
                        manager.update(&owned,|r|r.detail=Some(crate::lifecycle::safe_diagnostic(&error)))?;
                        // No live parent can be manufactured for failed startup.
                        let mut cleanup=Session::prepare(&manager,&p,&run,true)?;
                        return cleanup.reconcile(&manager,&owned);
                    },
                    Err(error)=>return Err(error),
                };
                if !cleanup {
                    if let Err(error)=session.serve(&manager,&p,&owned,&receiver) {
                        // Diagnostic strings are contract errors, never guest output.
                        manager.update(&owned,|r|r.detail=Some(crate::lifecycle::safe_diagnostic(&error)))?;
                    }
                }
                session.reconcile(&manager,&owned)
            })).unwrap_or_else(|_|Err("Remote worker interrupted unexpectedly; reconcile its durable intent.".into()));
            if let Err(error)=result {
                let diagnostic=crate::lifecycle::safe_diagnostic(&error).chars().take(2048).collect::<String>();
                if manager.update(&owned,|r| {r.phase=Phase::Unconfirmed;r.detail=Some(diagnostic.clone())}).is_err() {
                    // Keep the older durable intent recoverable and show the
                    // actual stopped worker even if this new write failed.
                    let mut run=owned.run.lock().unwrap_or_else(|e|e.into_inner());
                    run.phase=Phase::Unconfirmed;
                    run.detail=Some(format!("{diagnostic} Remote journal write failed; original cleanup intent retained."));
                }
            }
            *owned.sender.lock().unwrap_or_else(|e|e.into_inner())=None;
            owned.finished.store(true,Ordering::Release);
        });
        if let Err(error) = result {
            entry.finished.store(true, Ordering::Release);
            *entry.sender.lock().unwrap_or_else(|e| e.into_inner()) = None;
            return Err(format!(
                "Remote worker could not start; intent retained for reconciliation: {error}"
            ));
        }
        Ok(())
    }
}
