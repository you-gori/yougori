//! Existing-engine operations for the pinned SSH management bridge. A durable
//! intent precedes VM creation. Neither a retry nor an engine restart recreates
//! that identity, and guest commands are never automatically repeated.
use super::*;
use crate::sandbox::vm_service::{CommandId, SandboxStatus};
use crate::sandbox_contract::remote_ssh::{
    RemoteManagementRequest as Request, RemoteVmBinding, RemoteVmObservation,
};
use serde::{Deserialize, Serialize};

const MAX_RECORDS: usize = 256;
const MAX_RECORD_BYTES: u64 = 64 * 1024;
const MAX_TERMINALS: usize = 4096;
const MAX_TERMINAL_BYTES: u64 = 16 * 1024;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Terminal {
    version: u32,
    run: Digest,
    /// None means creation was durably cancelled before any launch intent.
    settings: Option<(u64, u64)>,
    receipt: Value,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Intent {
    version: u32,
    run: Digest,
    execution: ExecutionId,
    engine: ProcessIdentity,
    memory_mib: u64,
    lifetime_seconds: u64,
    observation: Option<RemoteVmObservation>,
    #[serde(default)]
    launch_failure: Option<String>,
    /// Only an actual native end or exact backend stop proof may populate this.
    ended: Option<Value>,
}

fn own_process() -> Result<ProcessIdentity, String> {
    ProcessIdentity::holder_of(std::process::id())
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "The engine's process identity is unavailable.".into())
}

fn executable_digest() -> Result<Digest, String> {
    static ID: OnceLock<Result<Digest, String>> = OnceLock::new();
    ID.get_or_init(|| {
        // An updater can replace the Linux installation path while this engine
        // runs. Measure this process's image, not a later executable at that path.
        #[cfg(target_os = "linux")]
        {
            use sha2::{Digest as _, Sha256};
            use std::io::Read;
            // This fixed kernel-owned magic link is intentionally followed.
            // sha256_file refuses links in all caller-selected artifact paths;
            // weakening that policy to measure this process would be incorrect.
            let mut image = fs::File::open("/proc/self/exe").map_err(|e| e.to_string())?;
            let mut hash = Sha256::new();
            let mut buffer = [0u8; 64 * 1024];
            loop {
                let count = image.read(&mut buffer).map_err(|e| e.to_string())?;
                if count == 0 {
                    break;
                }
                hash.update(&buffer[..count]);
            }
            Ok(Digest::from_bytes(hash.finalize().into()))
        }
        #[cfg(not(target_os = "linux"))]
        {
            let executable = std::env::current_exe().map_err(|e| e.to_string())?;
            artifacts::sha256_file(&executable).map_err(|e| e.to_string())
        }
    })
    .clone()
}

fn command_id(command: u32) -> Result<CommandId, String> {
    if command == 0 {
        return Err("A nonzero command identity is required.".into());
    }
    serde_json::from_value(json!(command)).map_err(|_| "Invalid command identity.".into())
}

impl Production {
    fn terminal_path(&self, run: Digest) -> Result<PathBuf, String> {
        let root = self
            .state_file
            .parent()
            .ok_or("The service has no data directory.")?
            .join("remote-terminal");
        fs::create_dir_all(&root).map_err(|e| e.to_string())?;
        Ok(root.join(format!("{}.json", run.to_hex())))
    }

    fn read_terminal(&self, run: Digest) -> Result<Option<Terminal>, String> {
        use std::io::Read;
        let file = match fs::File::open(self.terminal_path(run)?) {
            Ok(file) => file,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.to_string()),
        };
        let mut bytes = Vec::new();
        file.take(MAX_TERMINAL_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|e| e.to_string())?;
        if bytes.len() as u64 > MAX_TERMINAL_BYTES {
            return Err("Remote terminal record exceeds its bound.".into());
        }
        let terminal: Terminal = serde_json::from_slice(&bytes)
            .map_err(|_| "Invalid remote terminal record; creation stays refused.")?;
        let valid_receipt = if terminal.settings.is_none() {
            terminal.receipt
                == json!({"state":"creation_cancelled","run":run,"server_power_changed":false,"durable":true})
        } else {
            crate::sandbox_contract::remote_ssh::confirmed_remote_end(run, None, &terminal.receipt)
                .is_ok()
        };
        if terminal.version != 1 || terminal.run != run || !valid_receipt {
            return Err("Inconsistent remote terminal record; creation stays refused.".into());
        }
        Ok(Some(terminal))
    }

    /// A terminal receipt must be durable before the larger launch record is
    /// removed. A crash between these steps keeps both; the terminal wins.
    fn save_terminal(&self, terminal: &Terminal) -> Result<(), String> {
        let _serial = self
            .remote_management
            .lock()
            .map_err(|_| "Remote journal lock is unavailable.")?;
        let path = self.terminal_path(terminal.run)?;
        if !path.exists()
            && fs::read_dir(path.parent().ok_or("No terminal directory")?)
                .map_err(|e| e.to_string())?
                .take(MAX_TERMINALS + 1)
                .count()
                >= MAX_TERMINALS
        {
            return Err("Remote terminal history is full; replay protection was retained and no history was discarded.".into());
        }
        let bytes = serde_json::to_vec(terminal).map_err(|e| e.to_string())?;
        if bytes.len() as u64 > MAX_TERMINAL_BYTES {
            return Err("Remote terminal receipt exceeds its bound.".into());
        }
        write_atomic(&path, &bytes).map_err(|e| e.to_string())?;
        if terminal.settings.is_some() {
            match fs::remove_file(self.remote_path(terminal.run)?) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e.to_string()),
            }
        }
        Ok(())
    }

    fn archive_remote(&self, record: &Intent, end: &Value) {
        // The complete end proof already exists in the launch record. If bounded
        // compaction fails, retain that record; cleanup itself remains confirmed.
        let _ = self.save_terminal(&Terminal {
            version: 1,
            run: record.run,
            settings: Some((record.memory_mib, record.lifetime_seconds)),
            receipt: end.clone(),
        });
    }

    fn remote_outcome(&self, binding: RemoteVmBinding, command: u32) -> Result<Value, String> {
        let outcome = self
            .service
            .try_exec_outcome(
                &SandboxId::new(binding.execution.clone()),
                command_id(command)?,
            )
            .map_err(|e| e.to_string())?;
        Ok(
            json!({"state":if outcome.is_some(){"completed"}else{"running"},"binding":binding,
            "command":command,"outcome":outcome,"source":"guest_report"}),
        )
    }

    fn remote_path(&self, run: Digest) -> Result<PathBuf, String> {
        let root = self
            .state_file
            .parent()
            .ok_or("The service has no data directory.")?
            .join("remote-runs");
        fs::create_dir_all(&root).map_err(|e| e.to_string())?;
        Ok(root.join(format!("{}.json", run.to_hex())))
    }

    fn read_remote(&self, run: Digest) -> Result<Option<Intent>, String> {
        use std::io::Read;
        let path = self.remote_path(run)?;
        let file = match fs::File::open(path) {
            Ok(file) => file,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.to_string()),
        };
        let mut bytes = Vec::new();
        file.take(MAX_RECORD_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|e| e.to_string())?;
        if bytes.len() as u64 > MAX_RECORD_BYTES {
            return Err("The remote intent exceeds its bound.".into());
        }
        let record: Intent = serde_json::from_slice(&bytes)
            .map_err(|_| "The remote intent is invalid; it must not be recreated.")?;
        if record.version != 1
            || record.run != run
            || record
                .observation
                .as_ref()
                .is_some_and(|o| o.binding.run != run || o.binding.execution != record.execution)
        {
            return Err("The remote intent's identity is inconsistent.".into());
        }
        Ok(Some(record))
    }

    fn save_remote(&self, record: &Intent) -> Result<(), String> {
        let bytes = serde_json::to_vec(record).map_err(|e| e.to_string())?;
        if bytes.len() as u64 > MAX_RECORD_BYTES {
            return Err("The remote intent exceeds its bound.".into());
        }
        write_atomic(&self.remote_path(record.run)?, &bytes).map_err(|e| e.to_string())
    }

    fn remote_status(&self, record: &Intent) -> Option<SandboxStatus> {
        self.service
            .status()
            .into_iter()
            .find(|s| s.sandbox.execution() == &record.execution)
    }

    fn observe_remote(&self, record: &mut Intent) -> Result<RemoteVmObservation, String> {
        if record.ended.is_some() || record.engine != own_process()? {
            return Err("This remote run ended or belongs to an earlier engine; reconcile it, never revive it.".into());
        }
        let id = SandboxId::new(record.execution.clone());
        let status = self.service.observe_vm(&id).map_err(|e| e.to_string())?;
        if status.remote_control.as_ref().is_none_or(|c| c.closed) {
            return Err("This run has no live remote delegation gate.".into());
        }
        let boot = status.boot.ok_or("The remote VM has no boot identity.")?;
        let process = status
            .process
            .ok_or("The remote VM has no observed process.")?;
        if !process.running().map_err(|e| e.to_string())? {
            return Err("The exact remote VM process no longer runs.".into());
        }
        let launch = status
            .launch_record
            .ok_or("The remote VM has no launch record.")?;
        let accelerator = launch
            .accelerator
            .value()
            .hypervisor()
            .ok_or("The remote workload is not hardware-virtualized.")?;
        let observed = RemoteVmObservation {
            binding: RemoteVmBinding {
                run: record.run,
                execution: record.execution.clone(),
                boot,
            },
            engine_sha256: executable_digest()?,
            process,
            backend: self.backend.clone(),
            accelerator,
            configuration: launch.configuration,
            guest_image: launch.guest_image,
            launch_record: launch.identity,
        };
        if record
            .observation
            .as_ref()
            .is_some_and(|old| old != &observed)
        {
            return Err(
                "The remote VM observation changed; its identity cannot be replaced.".into(),
            );
        }
        record.observation = Some(observed.clone());
        self.save_remote(record)?;
        Ok(observed)
    }

    fn match_remote(record: &Intent, binding: &RemoteVmBinding) -> Result<SandboxId, String> {
        if record
            .observation
            .as_ref()
            .is_none_or(|o| &o.binding != binding)
        {
            return Err(
                "The remote run, execution and boot do not match the persisted binding.".into(),
            );
        }
        Ok(SandboxId::new(binding.execution.clone()))
    }

    fn reconcile_remote(&self, record: &mut Intent, stop: bool) -> Result<Value, String> {
        if let Some(end) = &record.ended {
            self.archive_remote(record, end);
            return Ok(end.clone());
        }
        let id = SandboxId::new(record.execution.clone());
        if stop && self.remote_status(record).is_some() {
            // close first: even an uncertain cleanup cannot admit more work.
            self.service.remote_close(&id);
            if let Ok(report) = self.stop_sandbox(&id) {
                let exact = report["vm_stop"]["vm_stop"] == "stopped"
                    && report["sandbox"] == json!(id)
                    && match record.observation.as_ref() {
                        Some(o) => report["vm_stop"]["process"] == json!(o.process),
                        // A failed bootstrap may stop before its first ready
                        // observation. Its current service's exact stop proof is
                        // still valid for the identity persisted before launch.
                        None => {
                            record.engine == own_process()?
                                && serde_json::from_value::<ProcessIdentity>(
                                    report["vm_stop"]["process"].clone(),
                                )
                                .is_ok()
                        }
                    };
                if exact {
                    let end = json!({"state":"ended","run":record.run,"execution":record.execution,
                        "binding":record.observation.as_ref().map(|o| &o.binding),
                        "proof_source":"backend_stop","proof":report["vm_stop"],"server_power_changed":false});
                    record.ended = Some(end.clone());
                    self.save_remote(record)?;
                    self.archive_remote(record, &end);
                    return Ok(end);
                }
            }
        }
        let directory = self
            .state_file
            .parent()
            .ok_or("No data directory")?
            .join(SUPERVISOR_DIRECTORY);
        if let Some(end) = super::super::supervisor::journal::find_remote_end(
            &directory,
            record.engine,
            &record.execution,
            record.observation.as_ref().map(|o| o.process),
        )? {
            let end = json!({"state":"ended","run":record.run,"execution":record.execution,
                "binding":record.observation.as_ref().map(|o| &o.binding),
                "proof_source":"native_supervisor","proof":end,"server_power_changed":false});
            record.ended = Some(end.clone());
            self.save_remote(record)?;
            self.archive_remote(record, &end);
            return Ok(end);
        }
        // Absence from a PID list, missing service state, SSH failure, and a lease
        // expiry alone are deliberately not reported as confirmed cleanup.
        Ok(
            json!({"state":"unconfirmed","run":record.run,"execution":record.execution,
            "observation":record.observation,"server_power_changed":false,
            "launch_failure":record.launch_failure,
            "detail":"No exact native termination proof is available yet. This run will not be recreated."}),
        )
    }

    pub(super) fn remote_manage(&self, request: Request) -> Result<Value, String> {
        let run = request.run();
        // A slow boot serializes only its own run. It must not hold up command
        // polling or cleanup of unrelated already-running delegated VMs.
        let serial = {
            let mut active = self
                .remote_management
                .lock()
                .map_err(|_| "Remote management lock is unavailable.")?;
            active.retain(|_, lock| lock.strong_count() > 0);
            if let Some(lock) = active.get(&run).and_then(std::sync::Weak::upgrade) {
                lock
            } else {
                if active.len() >= 64 {
                    return Err("Too many concurrent remote management runs.".into());
                }
                let lock = Arc::new(std::sync::Mutex::new(()));
                active.insert(run, Arc::downgrade(&lock));
                lock
            }
        };
        let _serial = serial
            .lock()
            .map_err(|_| "This remote run's lock is unavailable.")?;
        if let Some(terminal) = self.read_terminal(run)? {
            match &request {
                Request::Launch {
                    memory_mib,
                    lifetime_seconds,
                    ..
                } => {
                    if terminal
                        .settings
                        .is_some_and(|settings| settings != (*memory_mib, *lifetime_seconds))
                    {
                        return Err(
                            "A remote run identity cannot be reused with different settings."
                                .into(),
                        );
                    }
                    return Ok(terminal.receipt);
                }
                Request::Reconcile { .. } => return Ok(terminal.receipt),
                Request::Stop { binding } | Request::Outcome { binding, .. }
                    if terminal.receipt["binding"] == json!(binding) =>
                {
                    return match request {
                        Request::Outcome { binding, command } => {
                            self.remote_outcome(binding, command)
                        }
                        _ => Ok(terminal.receipt),
                    };
                }
                _ => return Err("This remote run is terminal and cannot accept new work.".into()),
            }
        }
        let mut record = self.read_remote(run)?;
        if record.is_none() && matches!(&request, Request::Reconcile { .. }) {
            // Reconciliation can overtake a delayed launch. Persist cancellation
            // under this same run lock, so that later request cannot create a VM.
            let receipt = json!({"state":"creation_cancelled","run":run,"server_power_changed":false,"durable":true});
            self.save_terminal(&Terminal {
                version: 1,
                run,
                settings: None,
                receipt: receipt.clone(),
            })?;
            return Ok(receipt);
        }
        if let Request::Launch {
            memory_mib,
            lifetime_seconds,
            ..
        } = &request
        {
            let memory = memory_mib
                .checked_mul(MIB_BYTES)
                .ok_or("Memory size overflow.")?;
            if !(LEAST_LAUNCH_MEMORY_BYTES..=MAX_LAUNCH_MEMORY_BYTES).contains(&memory)
                || !(1..=86400).contains(lifetime_seconds)
            {
                return Err("Remote launch needs 320..65536 MiB and 1..86400 seconds.".into());
            }
            if let Some(existing) = record.as_mut() {
                if existing.memory_mib != *memory_mib
                    || existing.lifetime_seconds != *lifetime_seconds
                {
                    return Err(
                        "A remote run identity cannot be reused with different settings.".into(),
                    );
                }
                return match self.observe_remote(existing) {
                    Ok(observation) => Ok(json!({"state":"ready","observation":observation})),
                    Err(_) => self.reconcile_remote(existing, false),
                };
            }
            let mut intent = Intent {
                version: 1,
                run,
                execution: ExecutionId::generate(),
                engine: own_process()?,
                memory_mib: *memory_mib,
                lifetime_seconds: *lifetime_seconds,
                observation: None,
                launch_failure: None,
                ended: None,
            };
            {
                let _create = self
                    .remote_management
                    .lock()
                    .map_err(|_| "Remote management lock is unavailable.")?;
                let path = self.remote_path(run)?;
                if fs::read_dir(path.parent().ok_or("No remote directory")?)
                    .map_err(|e| e.to_string())?
                    .take(MAX_RECORDS + 1)
                    .count()
                    >= MAX_RECORDS
                {
                    return Err("The remote run journal is full; retain and archive its completed records before adding more.".into());
                }
                self.save_remote(&intent)?; // Must succeed before any VM starts.
            }
            let spec = LaunchSpec {
            gpu: false,
            gpu_memory: Vec::new(),
            internet: false,
            targets: None,
            owner_session: false,
                tenant: TenantId::new(TENANT).map_err(|e| e.to_string())?,
                resources: VmResources {
                    memory_bytes: memory,
                    cpu_slots: 1,
                },
                egress_endpoints: Vec::new(),
                workload_image: None,
                idle_limit: None,
                lifetime_limit: Some(Duration::from_secs(*lifetime_seconds)),
                published: Vec::new(),
                connect: Vec::new(),
            };
            let launch =
                self.launch_mode_identified(spec, None, None, true, Some(intent.execution.clone()));
            // Preserve the supervisor even when launch refuses after creation.
            if let Err(error) = self.checkpoint() {
                self.service
                    .remote_close(&SandboxId::new(intent.execution.clone()));
                return Err(error);
            }
            if let Err(error) = launch {
                intent.launch_failure = Some(
                    crate::lifecycle::safe_diagnostic(&error)
                        .chars()
                        .take(2048)
                        .collect(),
                );
                self.save_remote(&intent)?;
                return self.reconcile_remote(&mut intent, true);
            }
            return match self.observe_remote(&mut intent) {
                Ok(observation) => Ok(json!({"state":"ready","observation":observation})),
                Err(error) => {
                    self.service
                        .remote_close(&SandboxId::new(intent.execution.clone()));
                    intent.launch_failure = Some(
                        crate::lifecycle::safe_diagnostic(&error)
                            .chars()
                            .take(2048)
                            .collect(),
                    );
                    self.save_remote(&intent)?;
                    Err(error)
                }
            };
        }
        let mut record = record
            .ok_or("This engine has no intent for that remote run; no resource was acted on.")?;
        match request {
            Request::Probe { binding } => {
                Self::match_remote(&record, &binding)?;
                let observation = self.observe_remote(&mut record)?;
                let control = self.service.remote_view(&SandboxId::new(binding.execution));
                Ok(json!({"state":"ready","observation":observation,"control":control}))
            }
            Request::Start {
                binding,
                input_hex,
                output_bytes,
                deadline_seconds,
            } => {
                let id = Self::match_remote(&record, &binding)?;
                self.observe_remote(&mut record)?;
                self.responses().admits_exec(id.execution())?;
                if input_hex.len() > 2 * crate::sandbox::vm_service::MAX_COMMAND_INPUT_BYTES
                    || !(1..=MAX_COMMAND_OUTPUT_BYTES.min(512 * 1024)).contains(&output_bytes)
                    || !(1..=MAX_EXEC_DEADLINE.as_secs()).contains(&deadline_seconds)
                {
                    return Err(
                        "Remote command input, output or deadline exceeds its bound.".into(),
                    );
                }
                let input = hex::decode(&input_hex).map_err(|_| "Invalid command encoding.");
                // Do not retain the hex copy after handing its bytes to the existing service.
                input_hex.into_bytes().fill(0);
                let command = self
                    .service
                    .start_exec(
                        &id,
                        ExecRequest::new(
                            input?,
                            output_bytes,
                            Duration::from_secs(deadline_seconds),
                        ),
                    )
                    .map_err(|e| e.to_string())?;
                Ok(json!({"state":"started","binding":binding,"command":command}))
            }
            Request::Outcome { binding, command } => {
                Self::match_remote(&record, &binding)?;
                self.remote_outcome(binding, command)
            }
            Request::Cancel { binding, command } => {
                let id = Self::match_remote(&record, &binding)?;
                self.service
                    .cancel(&id, command_id(command)?)
                    .map_err(|e| e.to_string())?;
                Ok(json!({"state":"cancelled","binding":binding,"command":command}))
            }
            Request::Stop { binding } => {
                Self::match_remote(&record, &binding)?;
                self.reconcile_remote(&mut record, true)
            }
            Request::Reconcile { .. } => self.reconcile_remote(&mut record, true),
            Request::Launch { .. } => unreachable!("launch handled above"),
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    #[test]
    fn the_running_image_uses_the_kernel_link_without_relaxing_artifact_paths() {
        let path = std::env::current_exe().unwrap();
        let expected = super::artifacts::sha256_file(&path).unwrap();
        assert_eq!(super::executable_digest().unwrap(), expected);
        assert!(super::artifacts::sha256_file(std::path::Path::new("/proc/self/exe")).is_err());
    }
}
