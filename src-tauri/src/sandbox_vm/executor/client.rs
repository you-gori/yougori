//! The engine's side of the executor (module docs in `mod.rs`): starts the executor process
//! (this binary in its executor mode) in a kill-on-close job, admits it on the control pipe
//! by PX1 identity, and speaks the protocol one request at a time. The executor's death is
//! visible here through its process handle; the engine starts another on its next need.

use std::collections::BTreeSet;
use std::fmt;
use std::path::Path;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use crate::foundation::ids::ExecutionId;
use crate::foundation::process::{
    Escalation, HostProcess, JobSettings, LoweredIntegrity, ProcessIdentity, ProcessRole,
    RestrictedStart, SandboxDesktop, StartMitigation,
};
use crate::sandbox_contract::relay_link::control_pipe::{ControlListener, ControlPipe};
use crate::sandbox_contract::relay_link::RelayPipeName;

use super::protocol::{decode_line, encode_line, ExecutorReply, ExecutorRequest, PROTOCOL_VERSION};
use super::EXECUTOR_MODE;

/// How the executor is ended when the engine lets it go.
pub const END_ESCALATION: Escalation = Escalation {
    grace: Duration::from_secs(5),
    kill_wait: Duration::from_secs(5),
};

/// The executor's job: itself and its relays (each in a nested job of its own), a memory
/// bound for all of them together, ended on an unhandled exception, no UI access.
pub const EXECUTOR_JOB: JobSettings = JobSettings {
    active_process_limit: 64,
    job_memory_limit_bytes: 2 << 30,
    die_on_unhandled_exception: true,
    ui_restrictions: true,
};

/// Starts of executors by this engine, to name each one's desktop.
static STARTS: AtomicU64 = AtomicU64::new(0);

/// The executor's token: the engine's own with every privilege disabled and Administrators
/// deny-only, at the medium label, with no restricting SID (the credential store and the
/// owner-only control pipe refuse every restricting SID and every lower label: the
/// diagnostic `executor_needs_under_token_variants`, 30 October 2026). The start adds the
/// job, the four start mitigations and a desktop of its own, and inherits no handle.
pub fn executor_start() -> Result<RestrictedStart, String> {
    let number = STARTS.fetch_add(1, Ordering::Relaxed) + 1;
    // Its own desktop, which also grants ALL APPLICATION PACKAGES the sandbox access: the
    // AppContainer relays inherit it and need it to initialize (measured 30 October 2026:
    // on a desktop without that grant no relay reached its link pipe).
    let desktop = SandboxDesktop::for_executor(
        &format!("ygx-{}-{number}", std::process::id()),
        LoweredIntegrity::Medium,
    )
    .map_err(|error| format!("the executor's desktop could not be created: {error}"))?;
    Ok(RestrictedStart {
        restricting: BTreeSet::new(),
        integrity: LoweredIntegrity::Medium,
        job: EXECUTOR_JOB,
        mitigations: StartMitigation::ALL.into_iter().collect(),
        stderr: None,
        desktop,
    })
}

/// The engine's handle on its executor process.
pub struct ExecutorClient {
    process: HostProcess,
    pipe: ControlPipe,
    executor: ProcessIdentity,
    /// What the host saw of the executor while it was still suspended.
    observation: crate::foundation::process::StartObservation,
}

impl fmt::Debug for ExecutorClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExecutorClient")
            .field("executor", &self.executor)
            .finish_non_exhaustive()
    }
}

impl ExecutorClient {
    /// Starts `executable` as the executor and admits it (module notes). A process that
    /// never connects, is not the one started, or does not answer the hello is ended.
    pub fn start(executable: &Path, within: Duration) -> Result<Self, String> {
        let engine_pid = std::process::id();
        let name = RelayPipeName::new(format!(
            r"\\.\pipe\yougori-sandbox-executor-{engine_pid}-{}",
            uuid::Uuid::new_v4().simple()
        ))
        .map_err(|error| error.to_string())?;
        let mut listener = ControlListener::create(name.clone())
            .map_err(|error| format!("the control pipe could not be created: {error}"))?;
        let mut command = Command::new(executable);
        command
            .arg(EXECUTOR_MODE)
            .arg(name.as_str())
            .arg(engine_pid.to_string())
            .env_clear();
        // Only what the executor needs of the environment: the system root for its DLLs
        // and the relays' commands; the credential store needs no variable.
        if let Some(root) = std::env::var_os("SystemRoot") {
            command.env("SystemRoot", root);
        }
        // A disposable acceptance engine's executor keeps the data folder that sets its vault
        // service apart from the product's (`process::run_executor`, which refuses to start an
        // acceptance build without it). A product build has no such folder and passes nothing.
        if let Some(folder) = crate::acceptance::data_directory() {
            command.env("YOUGORI_ACCEPTANCE_DATA_DIR", folder);
        }
        let role = ProcessRole::SandboxExecutor {
            execution: ExecutionId::new(format!("sandbox-executor-{engine_pid}"))
                .map_err(|error| error.to_string())?,
        };
        let (process, observation) =
            HostProcess::spawn_restricted(&command, role, executor_start()?)
                .map_err(|error| format!("the executor could not be started: {error}"))?;
        let executor = process.identity();
        let pipe = match listener.accept(&executor, within) {
            Ok(pipe) => pipe,
            Err(error) => {
                let _ = process.terminate(END_ESCALATION);
                return Err(format!("the executor was not admitted: {error}"));
            }
        };
        let mut client = Self {
            process,
            pipe,
            executor,
            observation,
        };
        match client.request(
            &ExecutorRequest::Hello {
                version: PROTOCOL_VERSION,
                engine_pid,
            },
            within,
        ) {
            Ok(ExecutorReply::Hello { version, executor })
                if version == PROTOCOL_VERSION && executor == client.executor =>
            {
                Ok(client)
            }
            Ok(reply) => {
                let _ = client.process.terminate(END_ESCALATION);
                Err(format!("the executor's hello was refused: {reply:?}"))
            }
            Err(error) => {
                let _ = client.process.terminate(END_ESCALATION);
                Err(format!("the executor did not answer the hello: {error}"))
            }
        }
    }

    /// The executor's PX1 identity.
    pub fn identity(&self) -> ProcessIdentity {
        self.executor
    }

    /// Whether the executor's process still runs (its job has not ended).
    pub fn alive(&self) -> bool {
        self.process.check_ended().is_err()
    }

    /// What the host saw of the executor at its start.
    pub fn observation(&self) -> crate::foundation::process::StartObservation {
        self.observation
    }

    /// The host's read-back of the executor's token, job, mitigations and command line,
    /// through the handles it holds.
    pub fn restrictions(&self) -> Result<serde_json::Value, String> {
        let readback = self
            .process
            .read_restrictions()
            .map_err(|error| error.to_string())?;
        serde_json::to_value(readback).map_err(|error| error.to_string())
    }

    /// Sends `request` and waits at most `within` for its reply.
    pub fn request(
        &mut self,
        request: &ExecutorRequest,
        within: Duration,
    ) -> Result<ExecutorReply, String> {
        let line = encode_line(request).map_err(|error| error.to_string())?;
        self.pipe
            .send_line(&line, within)
            .map_err(|error| format!("the request could not be sent to the executor: {error}"))?;
        let reply = self
            .pipe
            .read_line(within)
            .map_err(|error| format!("the executor's reply could not be read: {error}"))?
            .ok_or_else(|| "the executor did not reply in time".to_owned())?;
        decode_line::<ExecutorReply>(&reply).map_err(|error| error.to_string())
    }
}

impl Drop for ExecutorClient {
    /// A handle the engine lets go ends its executor (and, through the executor's job, every
    /// relay it still held); a dead executor is observed, nothing more.
    fn drop(&mut self) {
        let _ = self.process.terminate(END_ESCALATION);
    }
}
