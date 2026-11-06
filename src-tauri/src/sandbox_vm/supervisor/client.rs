//! The engine's side of the lifetime supervisor (module docs in `mod.rs`): starts the
//! supervisor process (this binary in its supervisor mode) restricted as the executor is, in
//! a job of its own, admits it on the control pipe by PX1 identity, hands it at the hello a
//! handle to the engine's own process and to its own job, and speaks the protocol one
//! request at a time. Its death is visible here through its process handle.
//!
//! On Linux the supervisor starts in a cgroup of its own ([`supervisor_group`]: the same
//! memory bound, a few tasks, no network, a session of its own, no new privileges) as the
//! engine's account, which must be one that may end the VMs' groups (root: QEMU runs as an
//! account of its own); the control pipe is a socket in a private directory beside the
//! journals, and nothing is duplicated into it: it opens its own pidfds by identity.

#[cfg(windows)]
use std::collections::BTreeSet;
use std::fmt;
use std::path::Path;
use std::process::Command;
#[cfg(windows)]
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use crate::foundation::ids::ExecutionId;
#[cfg(target_os = "linux")]
use crate::foundation::process::LinuxContainment;
use crate::foundation::process::{Escalation, HostProcess, JobUsage, ProcessIdentity, ProcessRole};
#[cfg(windows)]
use crate::foundation::process::{
    JobSettings, LoweredIntegrity, RestrictedStart, SandboxDesktop, StartMitigation,
};
use crate::sandbox::vm_service::SharedVm;
use crate::sandbox_contract::relay_link::control_pipe::{ControlListener, ControlPipe};
#[cfg(windows)]
use crate::sandbox_contract::relay_link::RelayPipeName;

use super::protocol::{
    decode_line, encode_line, HeldEnd, SandboxTerms, SupervisorReply, SupervisorRequest,
    SupervisorSettings, Terms, PROTOCOL_VERSION,
};
use super::SUPERVISOR_MODE;

/// How a newly started supervisor is ended if its handshake fails before any VM
/// handles are transferred. A live holder is not killed for an IPC timeout.
pub const END_ESCALATION: Escalation = Escalation {
    grace: Duration::ZERO,
    kill_wait: Duration::from_secs(5),
};

/// How long one request may take.
pub const REQUEST_WITHIN: Duration = Duration::from_secs(10);

/// The supervisor's job: itself alone, a memory bound far inside the host ledger's
/// supervisor reserve (never granted to a workload: a tenth of the RAM, at least 1 GiB;
/// `model_runner::optimizer::capacity::host`), ended on an unhandled exception, no UI
/// access. Its process holds its own job, so the job outlives the engine's handle.
#[cfg(windows)]
pub const SUPERVISOR_JOB: JobSettings = JobSettings {
    active_process_limit: 1,
    job_memory_limit_bytes: SUPERVISOR_MEMORY_BYTES,
    die_on_unhandled_exception: true,
    ui_restrictions: true,
};

/// The most memory the supervisor may use, within the host ledger's supervisor reserve.
pub const SUPERVISOR_MEMORY_BYTES: u64 = 128 << 20;

/// The supervisor's group on Linux (module notes): [`SUPERVISOR_MEMORY_BYTES`], at most 16
/// tasks (its threads), no network, the engine's account (root: it owns the groups it ends)
/// with no capability at all, a nice value of -5 so its ticks run under load, and no
/// parent-death signal: it outlives the engine.
#[cfg(target_os = "linux")]
pub fn supervisor_group() -> LinuxContainment {
    LinuxContainment {
        memory_limit_bytes: SUPERVISOR_MEMORY_BYTES,
        max_processes: 16,
        run_as: None,
        no_network: true,
        end_with_host: false,
        drop_capabilities: true,
        nice: Some(-5),
    }
}

/// Starts of supervisors by this engine, to name each one's desktop.
#[cfg(windows)]
static STARTS: AtomicU64 = AtomicU64::new(0);

/// The supervisor's token, as the executor's: the engine's own with every privilege
/// disabled and Administrators deny-only, at the medium label, with no restricting SID (the
/// owner-only control pipe refuses every restricting SID and every lower label), on a
/// desktop of its own, inheriting no handle; the job above and the four start mitigations.
#[cfg(windows)]
pub fn supervisor_start() -> Result<RestrictedStart, String> {
    let number = STARTS.fetch_add(1, Ordering::Relaxed) + 1;
    let desktop = SandboxDesktop::for_start(
        &format!("ygs-{}-{number}", std::process::id()),
        &BTreeSet::new(),
        LoweredIntegrity::Medium,
    )
    .map_err(|error| format!("the supervisor's desktop could not be created: {error}"))?;
    Ok(RestrictedStart {
        restricting: BTreeSet::new(),
        integrity: LoweredIntegrity::Medium,
        job: SUPERVISOR_JOB,
        mitigations: StartMitigation::ALL.into_iter().collect(),
        stderr: None,
        desktop,
    })
}

/// The engine's handle on its supervisor process.
pub struct SupervisorClient {
    process: HostProcess,
    pipe: Option<ControlPipe>,
    supervisor: ProcessIdentity,
}

impl fmt::Debug for SupervisorClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SupervisorClient")
            .field("supervisor", &self.supervisor)
            .finish_non_exhaustive()
    }
}

impl SupervisorClient {
    /// Starts `executable` as the supervisor writing its journal in `journal_dir`, and
    /// admits it (module notes). A process that never connects, is not the one started, or
    /// does not answer the hello is ended.
    pub fn start(
        executable: &Path,
        journal_dir: &Path,
        settings: SupervisorSettings,
        within: Duration,
    ) -> Result<Self, String> {
        let engine_pid = std::process::id();
        let engine = ProcessIdentity::holder_of(engine_pid)
            .map_err(|error| error.to_string())?
            .ok_or("the engine's own process could not be read")?;
        #[cfg(windows)]
        let name = RelayPipeName::new(format!(
            r"\\.\pipe\yougori-sandbox-supervisor-{engine_pid}-{}",
            uuid::Uuid::new_v4().simple()
        ))
        .map_err(|error| error.to_string())?;
        // Beside the journals, in a directory of the engine's account alone.
        #[cfg(target_os = "linux")]
        let name = crate::sandbox_contract::relay_link::control_pipe::socket_in(
            &journal_dir.parent().unwrap_or(journal_dir).join("sockets"),
            "supervisor",
        )
        .map_err(|error| error.to_string())?;
        let mut listener = ControlListener::create(name.clone())
            .map_err(|error| format!("the control pipe could not be created: {error}"))?;
        let mut command = Command::new(executable);
        command
            .arg(SUPERVISOR_MODE)
            .arg(name.as_str())
            .arg(engine_pid.to_string())
            .arg(journal_dir)
            .env_clear();
        if let Some(root) = std::env::var_os("SystemRoot") {
            command.env("SystemRoot", root);
        }
        // The engine's base for its groups, so the supervisor knows its own group as one of
        // the host's when it leaves and removes it (`process::leave_own_group`).
        #[cfg(target_os = "linux")]
        if let Some(base) = std::env::var_os("YOUGORI_CGROUP_BASE") {
            command.env("YOUGORI_CGROUP_BASE", base);
        }
        let role = ProcessRole::SandboxSupervisor {
            execution: ExecutionId::new(format!("sandbox-supervisor-{engine_pid}"))
                .map_err(|error| error.to_string())?,
        };
        #[cfg(windows)]
        let (process, _observation) =
            HostProcess::spawn_restricted(&command, role, supervisor_start()?)
                .map_err(|error| format!("the supervisor could not be started: {error}"))?;
        #[cfg(target_os = "linux")]
        let process = HostProcess::spawn_contained(&mut command, role, &supervisor_group())
            .map_err(|error| format!("the supervisor could not be started: {error}"))?;
        let supervisor = process.identity();
        let ended = |process: &HostProcess| {
            let _ = process.terminate(END_ESCALATION);
        };
        let pipe = match listener.accept(&supervisor, within) {
            Ok(pipe) => pipe,
            Err(error) => {
                ended(&process);
                return Err(format!("the supervisor was not admitted: {error}"));
            }
        };
        let handles = HostProcess::share_this_host_with(&process).and_then(|engine_handle| {
            match process.share_own_job() {
                Ok(job) => Ok((engine_handle, job)),
                Err(error) => {
                    process.close_shared(engine_handle);
                    Err(error)
                }
            }
        });
        let (engine_handle, own_job_handle) = match handles {
            Ok(handles) => handles,
            Err(error) => {
                ended(&process);
                return Err(format!(
                    "the supervisor's handles could not be given: {error}"
                ));
            }
        };
        let mut client = Self {
            process,
            pipe: Some(pipe),
            supervisor,
        };
        match client.request(
            &SupervisorRequest::Hello {
                version: PROTOCOL_VERSION,
                engine,
                engine_handle,
                own_job_handle,
                settings,
            },
            within,
        ) {
            Ok(SupervisorReply::Hello {
                version,
                supervisor: named,
            }) if version == PROTOCOL_VERSION && named == supervisor => Ok(client),
            Ok(reply) => {
                ended(&client.process);
                Err(format!("the supervisor's hello was refused: {reply:?}"))
            }
            Err(error) => {
                ended(&client.process);
                Err(format!("the supervisor did not answer the hello: {error}"))
            }
        }
    }

    /// The supervisor's PX1 identity.
    pub fn identity(&self) -> ProcessIdentity {
        self.supervisor
    }

    /// The process, for duplicating a VM's handles into it.
    pub fn process(&self) -> &HostProcess {
        &self.process
    }

    /// Whether the supervisor's process still runs.
    pub fn alive(&self) -> bool {
        self.process.check_ended().is_err()
    }

    /// An uncertain request permanently closes this connection. No later reply
    /// may be counted as acknowledgment of a newer deadline.
    pub fn can_control(&self) -> bool {
        self.pipe.is_some()
    }

    /// What its job has used: the supervisor's memory and CPU.
    pub fn usage(&self) -> Option<JobUsage> {
        self.process.usage().ok()
    }

    /// The host's read-back of the supervisor's token, job, mitigations and command line.
    #[cfg(windows)]
    pub fn restrictions(&self) -> Result<serde_json::Value, String> {
        let readback = self
            .process
            .read_restrictions()
            .map_err(|error| error.to_string())?;
        serde_json::to_value(readback).map_err(|error| error.to_string())
    }

    /// The host's read-back of the supervisor on Linux: its ids, capabilities, no new
    /// privileges and seccomp mode (`/proc/<pid>/status`), its group's limits and its
    /// network namespace's interfaces.
    #[cfg(target_os = "linux")]
    pub fn restrictions(&self) -> Result<serde_json::Value, String> {
        let pid = self.supervisor.pid;
        let read = |path: String| {
            std::fs::read_to_string(&path).map_err(|error| format!("{path}: {error}"))
        };
        let status =
            crate::sandbox::firecracker::parse_status(&read(format!("/proc/{pid}/status"))?)
                .map_err(|error| format!("the supervisor's status: {error:?}"))?;
        let interfaces =
            crate::sandbox::qemu::interfaces_of(&read(format!("/proc/{pid}/net/dev"))?);
        let group = self.process.group_path();
        let limit = |file: &str| {
            std::fs::read_to_string(group.join(file))
                .ok()
                .map(|text| text.trim().to_owned())
        };
        Ok(serde_json::json!({
            "status": status,
            "group": group.display().to_string(),
            "memory_max": limit("memory.max"),
            "pids_max": limit("pids.max"),
            "network_interfaces": interfaces,
        }))
    }

    /// Hands `vm` (its handles already duplicated into the supervisor) to the supervisor
    /// with its `terms`; how many VMs it holds. On a refusal before the supervisor took the
    /// handles, they are closed in it here.
    pub fn hold(&mut self, vm: &SharedVm, terms: Terms) -> Result<usize, String> {
        let reply = self.request(
            &SupervisorRequest::Hold {
                sandbox: vm.sandbox.execution().clone(),
                class: vm.class,
                process: vm.process,
                handles: vm.handles,
                terms,
            },
            REQUEST_WITHIN,
        );
        let close = |process: &HostProcess| {
            process.close_shared(vm.handles.job);
            process.close_shared(vm.handles.process);
        };
        match reply {
            Ok(SupervisorReply::Held { sandbox, holding })
                if &sandbox == vm.sandbox.execution() =>
            {
                Ok(holding)
            }
            Ok(SupervisorReply::HoldRefused {
                sandbox,
                detail,
                taken,
            }) if &sandbox == vm.sandbox.execution() => {
                if !taken {
                    close(&self.process);
                }
                Err(format!("the supervisor refused to hold the VM: {detail}"))
            }
            Ok(other) => {
                drop(self.pipe.take());
                Err(format!("the supervisor answered {other:?} to a hold"))
            }
            // Whether it took them is unknown. Keep its existing deadlines alive;
            // the engine refuses/stops the new VM instead of killing its guard.
            Err(error) => Err(error),
        }
    }

    /// The held sandboxes' terms (the heartbeat); the ends since the last reply, how many
    /// it holds and the VMs whose end it decided and has not observed yet.
    pub fn leases(
        &mut self,
        terms: Vec<SandboxTerms>,
    ) -> Result<(Vec<HeldEnd>, usize, Vec<ExecutionId>), String> {
        match self.request(&SupervisorRequest::Leases { terms }, REQUEST_WITHIN)? {
            SupervisorReply::Leases {
                ended,
                holding,
                unended,
            } => Ok((ended, holding, unended)),
            other => {
                drop(self.pipe.take());
                Err(format!("the supervisor answered {other:?} to the leases"))
            }
        }
    }

    /// Lets `sandbox` go; its end when the supervisor saw the VM end first.
    pub fn release(&mut self, sandbox: &ExecutionId) -> Result<Option<HeldEnd>, String> {
        match self.request(
            &SupervisorRequest::Release {
                sandbox: sandbox.clone(),
            },
            REQUEST_WITHIN,
        )? {
            SupervisorReply::Released {
                sandbox: released,
                end,
            } if &released == sandbox => Ok(end),
            other => {
                drop(self.pipe.take());
                Err(format!("the supervisor answered {other:?} to a release"))
            }
        }
    }

    /// Sends `request` and waits at most `within` for its reply.
    fn request(
        &mut self,
        request: &SupervisorRequest,
        within: Duration,
    ) -> Result<SupervisorReply, String> {
        let line = encode_line(request)?;
        let result = (|| {
            let pipe = self.pipe.as_mut().ok_or(
                "the supervisor control channel ended; its last deadlines remain enforced",
            )?;
            pipe.send_line(&line, within).map_err(|error| {
                format!("the request could not be sent to the supervisor: {error}")
            })?;
            let reply = pipe
                .read_line(within)
                .map_err(|error| format!("the supervisor's reply could not be read: {error}"))?
                .ok_or_else(|| "the supervisor did not reply in time".to_owned())?;
            decode_line::<SupervisorReply>(&reply)
        })();
        if result.is_err() {
            // Close the channel, not the process. It keeps its handles/deadlines
            // and exits itself once they end. No ambiguous reply is ever reused.
            drop(self.pipe.take());
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// PROVES the supervisor's job bound fits the host ledger's supervisor reserve, which no
    /// workload is ever granted (a tenth of the RAM, at least 1 GiB): its memory is reserved
    /// before any sandbox's (CORE-03), and the job holds the supervisor alone.
    #[cfg(windows)]
    #[test]
    fn the_supervisor_fits_the_ledgers_supervisor_reserve() {
        const SMALLEST_RESERVE: u64 = 1 << 30;
        assert!(SUPERVISOR_JOB.job_memory_limit_bytes <= SMALLEST_RESERVE / 4);
        assert_eq!(SUPERVISOR_JOB.active_process_limit, 1);
        assert!(SUPERVISOR_JOB.die_on_unhandled_exception && SUPERVISOR_JOB.ui_restrictions);
    }

    /// PROVES on Linux the supervisor's group bound fits the same reserve, and it has no
    /// network and runs as the engine's account (it ends the VMs' groups).
    #[cfg(target_os = "linux")]
    #[test]
    fn the_supervisor_group_fits_the_ledgers_supervisor_reserve() {
        const SMALLEST_RESERVE: u64 = 1 << 30;
        let group = supervisor_group();
        assert!(group.memory_limit_bytes <= SMALLEST_RESERVE / 4);
        assert!(group.no_network);
        assert!(group.run_as.is_none());
        assert!(!group.end_with_host, "the supervisor outlives the engine");
        assert!(
            group.drop_capabilities,
            "the supervisor holds no capability"
        );
    }
}
