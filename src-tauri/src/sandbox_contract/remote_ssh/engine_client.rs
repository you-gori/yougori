//! The home consumer of the existing remote engine, through V12 management gates.
//! A pinned operator's API report is ProviderApi evidence, never a local host probe.
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::{
    ManagementChannel, RemoteManagementRequest, RemoteVmBinding, RemoteVmObservation, SshOutcome,
    SshPort,
};
use crate::foundation::evidence::{
    Backend, BackendRelease, Capability, ConfigurationFingerprint, HostChange, Observation,
    ProbeAdapter, ProbeRegistry, RuntimeOffer, RuntimeSubject, SourceClass, Subject, SupportDetail,
    UnknownReason,
};
use crate::foundation::ids::{Clock, Digest, DigestBuilder, ExecutionCategory, MonotonicTime};
use crate::foundation::process::ProcessIdentity;
use crate::sandbox::backend::BackendKind;
use crate::sandbox_contract::remote::{
    ExecutionContext, HostAuthority, KnownHosts, ManagementAction, ManagementIdentity,
    OptionTerminator, ProgramPath, RemoteCapability, RemoteCapabilityEvidence, RemoteCommand,
    RemoteInvocation, RemoteSecret, RemoteVmAdapter, RemoteVmId,
};

pub struct EngineManagement<P: SshPort> {
    channel: ManagementChannel<P>,
    program: ProgramPath,
    endpoint: String,
    expected_engine: Digest,
}

#[derive(Serialize)]
struct RequestEnvelope<'a> {
    protocol: u32,
    params: &'a RemoteManagementRequest,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReplyEnvelope {
    protocol: u32,
    result: Value,
}

/// A native end reported by the pinned SSH host. This is remote operator evidence,
/// not a local process observation. Missing PID or lease expiry is insufficient.
pub fn confirmed_remote_end(
    run: Digest,
    expected: Option<&RemoteVmObservation>,
    reply: &Value,
) -> Result<ProcessIdentity, String> {
    if reply["state"] != "ended"
        || reply["run"] != serde_json::json!(run)
        || reply["server_power_changed"] != false
    {
        return Err("The remote run has no confirmed native end.".into());
    }
    let execution: crate::foundation::ids::ExecutionId =
        serde_json::from_value(reply["execution"].clone())
            .map_err(|_| "The remote end has no execution identity.")?;
    let process: ProcessIdentity = serde_json::from_value(reply["proof"]["process"].clone())
        .map_err(|_| "The remote end has no process identity.")?;
    if process.pid == 0 || process.start_time_ticks == 0 {
        return Err("Invalid remote end process identity.".into());
    }
    if let Some(expected) = expected {
        if expected.binding.run != run
            || expected.binding.execution != execution
            || expected.process != process
            || reply["binding"] != serde_json::json!(expected.binding)
        {
            return Err("The remote end is not for the exact observed VM.".into());
        }
    }
    let proof = &reply["proof"];
    let confirmed = match reply["proof_source"].as_str() {
        Some("backend_stop") => proof["vm_stop"] == "stopped",
        Some("native_supervisor") => {
            proof["sandbox"] == serde_json::json!(execution)
                && proof["job_processes"]
                    .as_u64()
                    .is_some_and(|count| count > 0)
        }
        _ => false,
    };
    if !confirmed {
        return Err("Remote cleanup lacks an exact native stop proof.".into());
    }
    Ok(process)
}

/// Cancellation before creation is a durable no-replay receipt, not VM end proof.
pub fn confirmed_creation_cancelled(run: Digest, reply: &Value) -> bool {
    *reply
        == serde_json::json!({"state":"creation_cancelled","run":run,
        "server_power_changed":false,"durable":true})
}

impl<P: SshPort> EngineManagement<P> {
    pub fn new(
        channel: ManagementChannel<P>,
        program: ProgramPath,
        endpoint: String,
        expected_engine: Digest,
    ) -> Result<Self, String> {
        if endpoint.is_empty() || endpoint.len() > 1024 || endpoint.chars().any(char::is_control) {
            return Err("Invalid remote engine endpoint.".into());
        }
        Ok(Self {
            channel,
            program,
            endpoint,
            expected_engine,
        })
    }

    pub fn call<C: Clock>(
        &mut self,
        adapter: &mut RemoteVmAdapter<C>,
        authority: &mut dyn HostAuthority,
        known: &KnownHosts,
        identity: &ManagementIdentity,
        request: &RemoteManagementRequest,
    ) -> Result<Value, String> {
        use RemoteManagementRequest::*;
        let action = match request {
            Launch { .. } => ManagementAction::LaunchVm,
            Probe { .. } | Start { .. } => ManagementAction::SuperviseVm,
            Outcome { .. } => ManagementAction::CollectLogs,
            Cancel { .. } | Stop { .. } | Reconcile { .. } => ManagementAction::TerminateVm,
        };
        let command = RemoteCommand::new(self.program.clone(), OptionTerminator::NotSupported)
            .flag("--sandbox-remote-call")
            .and_then(|c| c.operand(&self.endpoint))
            .map_err(|e| e.to_string())?;
        let payload = serde_json::to_vec(&RequestEnvelope {
            protocol: 1,
            params: request,
        })
        .map_err(|_| "Cannot encode remote request.")?;
        let invocation = RemoteInvocation::new(
            identity,
            known,
            action,
            ExecutionContext::RemoteHostShell {
                host: identity.host(),
            },
            &command,
        )
        .and_then(|i| i.with_stdin(RemoteSecret::new(payload)))
        .map_err(|e| e.to_string())?;
        let call = self
            .channel
            .call(adapter, authority, known, identity, &invocation)
            .map_err(|e| e.to_string())?;
        if !matches!(call.run.outcome, SshOutcome::RemoteExit { code: 0 }) {
            // stdout/stderr may contain guest bytes or credentials. No replay and
            // no transport payload is copied into a durable diagnostic.
            let reason = match &call.run.outcome {
                SshOutcome::RemoteExit { code } => format!("remote bridge exited with {code}"),
                SshOutcome::HostKeyMismatch { .. } => "SSH host key verification failed".into(),
                SshOutcome::AuthenticationRefused { .. } => "SSH authentication refused".into(),
                SshOutcome::ConnectionFailed { failure } => {
                    format!("SSH connection failed: {failure:?}")
                }
                SshOutcome::TimedOut { phase } => format!("SSH timeout: {phase:?}"),
                SshOutcome::OutputOverBound { .. } => "SSH output exceeded its bound".into(),
                SshOutcome::Uncertain { cause } => format!("SSH result uncertain: {cause:?}"),
            };
            return Err(format!("Remote management did not confirm an outcome ({reason}); do not repeat a workload command."));
        }
        let envelope: ReplyEnvelope = serde_json::from_slice(&call.run.output.stdout)
            .map_err(|_| "Invalid remote management response; outcome is uncertain.")?;
        if envelope.protocol != 1 {
            return Err("Unsupported remote management protocol.".into());
        }
        Self::check_binding(request, &envelope.result)?;
        if envelope.result["state"] == "ready" {
            let observation: RemoteVmObservation =
                serde_json::from_value(envelope.result["observation"].clone())
                    .map_err(|_| "Invalid remote VM observation.")?;
            if observation.engine_sha256 != self.expected_engine
                || observation.backend.kind != BackendKind::Qemu
                || observation.backend.hypervisor != observation.accelerator
                || !matches!(
                    observation.accelerator,
                    crate::foundation::evidence::HypervisorKind::Kvm
                        | crate::foundation::evidence::HypervisorKind::Whpx
                )
            {
                return Err(
                    "The remote VM build or backend does not match the selected profile.".into(),
                );
            }
        }
        Ok(envelope.result)
    }

    fn check_binding(request: &RemoteManagementRequest, result: &Value) -> Result<(), String> {
        use RemoteManagementRequest::*;
        let state = result["state"]
            .as_str()
            .ok_or("Remote response has no state.")?;
        let binding = match request {
            Probe { binding }
            | Start { binding, .. }
            | Outcome { binding, .. }
            | Cancel { binding, .. }
            | Stop { binding } => Some(binding),
            Launch { .. } | Reconcile { .. } => None,
        };
        let valid_state = match request {
            Launch { .. } => matches!(
                state,
                "ready" | "ended" | "unconfirmed" | "creation_cancelled"
            ),
            Probe { .. } => state == "ready",
            Start { .. } => {
                state == "started"
                    && result["command"]
                        .as_u64()
                        .is_some_and(|c| c > 0 && c <= u32::MAX as u64)
            }
            Outcome { command, .. } => {
                matches!(state, "running" | "completed")
                    && result["command"].as_u64() == Some(u64::from(*command))
            }
            Cancel { command, .. } => {
                state == "cancelled" && result["command"].as_u64() == Some(u64::from(*command))
            }
            Stop { .. } => matches!(state, "ended" | "unconfirmed"),
            Reconcile { .. } => matches!(state, "ended" | "unconfirmed" | "creation_cancelled"),
        };
        if !valid_state {
            return Err("Remote response is not for this operation.".into());
        }
        if state == "creation_cancelled" {
            return if confirmed_creation_cancelled(request.run(), result) {
                Ok(())
            } else {
                Err("Invalid durable cancellation receipt.".into())
            };
        }
        if matches!(state, "ended" | "unconfirmed") {
            if result["run"] != serde_json::json!(request.run())
                || result["server_power_changed"] != false
            {
                return Err(
                    "Remote cleanup response names another run or changed its server.".into(),
                );
            }
            if let Some(expected) = binding {
                if result["execution"] != serde_json::json!(expected.execution)
                    || (state == "ended" && result["binding"] != serde_json::json!(expected))
                {
                    return Err("Remote cleanup response names another VM.".into());
                }
            }
            if state == "ended"
                && !matches!(
                    result["proof_source"].as_str(),
                    Some("backend_stop" | "native_supervisor")
                )
            {
                return Err("Remote cleanup has no recognized native proof.".into());
            }
        } else {
            let value = if state == "ready" {
                &result["observation"]["binding"]
            } else {
                &result["binding"]
            };
            let observed: RemoteVmBinding =
                serde_json::from_value(value.clone()).map_err(|_| "Missing remote VM binding.")?;
            if observed.run != request.run()
                || binding.is_some_and(|expected| expected != &observed)
            {
                return Err("Remote response names another run, VM or boot.".into());
            }
        }
        Ok(())
    }

    /// Ask the actual remote engine now. One-use evidence includes the SSH round
    /// trip in its age and cannot repeatedly turn a cached report into fresh proof.
    pub fn probe_runtime<C: Clock + Clone + 'static>(
        &mut self,
        adapter: &mut RemoteVmAdapter<C>,
        authority: &mut dyn HostAuthority,
        known: &KnownHosts,
        identity: &ManagementIdentity,
        binding: &RemoteVmBinding,
        clock: C,
    ) -> Result<(RemoteVmObservation, RuntimeOffer, RemoteCapabilityEvidence), String> {
        let started = clock.now();
        let reply = self.call(
            adapter,
            authority,
            known,
            identity,
            &RemoteManagementRequest::Probe {
                binding: binding.clone(),
            },
        )?;
        let observation: RemoteVmObservation = serde_json::from_value(reply["observation"].clone())
            .map_err(|_| "Invalid VM report.")?;
        identity.check_current(known).map_err(|e| e.to_string())?;
        let enrollment = known
            .enrollment(&identity.host())
            .ok_or("Host enrollment ended during its probe.")?;
        let runtime = RuntimeSubject {
            category: ExecutionCategory::VmSandbox,
            release: BackendRelease::new(Backend::Qemu, observation.backend.version.as_str())
                .map_err(|e| e.to_string())?,
            instance: binding.workload_identity(),
        };
        let configuration = ConfigurationFingerprint::from_digest(
            DigestBuilder::new("yougori/remote/observation/v1")
                .bytes(
                    &serde_json::to_vec(&observation).map_err(|_| "Cannot bind VM observation.")?,
                )
                .bytes(&serde_json::to_vec(enrollment).map_err(|_| "Cannot bind enrollment.")?)
                .finish(),
        );
        let evidence = RemoteCapabilityEvidence::observed(
            enrollment,
            ExecutionContext::VmWorkload {
                host: identity.host(),
                vm: RemoteVmId::new(runtime.instance),
            },
            RemoteCapability::VmRunning {
                hardware_accelerated: true,
            },
            started,
        );
        let mut registry = ProbeRegistry::new(clock.clone());
        registry
            .register(Box::new(RemoteObservationProbe {
                runtime: runtime.clone(),
                configuration,
                clock,
                started,
                consumed: AtomicBool::new(false),
            }))
            .map_err(|e| e.to_string())?;
        registry
            .refresh(
                Capability::RuntimeCategory,
                &Subject::Runtime(runtime.clone()),
            )
            .map_err(|e| e.to_string())?;
        let offer =
            RuntimeOffer::observe(&registry, runtime, Duration::from_secs(1), configuration)
                .map_err(|e| e.to_string())?;
        Ok((observation, offer, evidence))
    }
}

struct RemoteObservationProbe<C: Clock> {
    runtime: RuntimeSubject,
    configuration: ConfigurationFingerprint,
    clock: C,
    started: MonotonicTime,
    consumed: AtomicBool,
}
impl<C: Clock> ProbeAdapter for RemoteObservationProbe<C> {
    fn capability(&self) -> Capability {
        Capability::RuntimeCategory
    }
    fn source(&self) -> SourceClass {
        SourceClass::ProviderApi
    }
    fn host_changes(&self) -> Vec<HostChange> {
        Vec::new()
    }
    fn observes(&self, subject: &Subject) -> bool {
        subject == &Subject::Runtime(self.runtime.clone())
    }
    fn observe(&self, subject: &Subject) -> Observation {
        let fresh = self
            .clock
            .now()
            .checked_duration_since(self.started)
            .is_some_and(|age| age <= Duration::from_secs(3));
        if !self.observes(subject) || self.consumed.swap(true, Ordering::SeqCst) || !fresh {
            return Observation::unknown(
                self.configuration,
                Duration::from_secs(1),
                UnknownReason::InconsistentReport,
            );
        }
        Observation::supported(
            self.configuration,
            Duration::from_secs(1),
            SupportDetail::RuntimeCategory {
                category: ExecutionCategory::VmSandbox,
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn a_precreation_cancellation_is_exact_and_never_a_native_end() {
        let run = crate::foundation::ids::digest("remote-cancel-test", &[b"one"]);
        let receipt = serde_json::json!({"state":"creation_cancelled","run":run,"server_power_changed":false,"durable":true});
        assert!(confirmed_creation_cancelled(run, &receipt));
        assert!(confirmed_remote_end(run, None, &receipt).is_err());
        assert!(EngineManagement::<NoIo>::check_binding(
            &RemoteManagementRequest::Reconcile { run },
            &receipt
        )
        .is_ok());
        assert!(EngineManagement::<NoIo>::check_binding(
            &RemoteManagementRequest::Launch {
                run,
                memory_mib: 512,
                lifetime_seconds: 60
            },
            &receipt
        )
        .is_ok());
        let mut not_durable = receipt.clone();
        not_durable["durable"] = serde_json::json!(false);
        assert!(!confirmed_creation_cancelled(run, &not_durable));
        assert!(!confirmed_creation_cancelled(
            crate::foundation::ids::digest("remote-cancel-test", &[b"other"]),
            &receipt
        ));
        let mut extra = receipt;
        extra["process"] = serde_json::json!(3);
        assert!(!confirmed_creation_cancelled(run, &extra));
    }
    use crate::foundation::evidence::HypervisorKind;
    use crate::foundation::ids::{digest, ExecutionId, ManualClock, SandboxBootGeneration};
    use crate::sandbox::backend::BackendIdentity;
    use std::sync::Arc;

    struct NoIo;
    impl SshPort for NoIo {
        fn run(&mut self, _: &super::super::SshInvocation<'_>) -> super::super::SshOutput {
            panic!("this semantic test must not invoke SSH")
        }
    }

    fn observation() -> RemoteVmObservation {
        RemoteVmObservation {
            binding: RemoteVmBinding {
                run: digest("run", &[b"one"]),
                execution: ExecutionId::new("remote-one").unwrap(),
                boot: SandboxBootGeneration::new(1),
            },
            engine_sha256: digest("engine", &[b"one"]),
            process: ProcessIdentity {
                pid: 42,
                start_time_ticks: 123,
            },
            backend: BackendIdentity::new(
                BackendKind::Qemu,
                "11.0.3",
                digest("backend", &[b"one"]),
                HypervisorKind::Kvm,
            )
            .unwrap(),
            accelerator: HypervisorKind::Kvm,
            configuration: ConfigurationFingerprint::from_digest(digest(
                "configuration",
                &[b"one"],
            )),
            guest_image: digest("guest", &[b"one"]),
            launch_record: digest("launch", &[b"one"]),
        }
    }

    #[test]
    fn replies_cannot_substitute_run_boot_command_or_server_ownership() {
        let observed = observation();
        let b = observed.binding.clone();
        let request = RemoteManagementRequest::Outcome {
            binding: b.clone(),
            command: 7,
        };
        let mut reply = serde_json::json!({"state":"completed","binding":b,"command":7});
        assert!(EngineManagement::<NoIo>::check_binding(&request, &reply).is_ok());
        reply["command"] = serde_json::json!(8);
        assert!(EngineManagement::<NoIo>::check_binding(&request, &reply).is_err());
        reply["command"] = serde_json::json!(7);
        reply["binding"]["boot"] = serde_json::json!(2);
        assert!(EngineManagement::<NoIo>::check_binding(&request, &reply).is_err());
        let request = RemoteManagementRequest::Reconcile { run: b.run };
        let mut reply =
            serde_json::json!({"state":"unconfirmed","run":b.run,"server_power_changed":false});
        assert!(EngineManagement::<NoIo>::check_binding(&request, &reply).is_ok());
        reply["run"] = serde_json::json!(digest("run", &[b"other"]));
        assert!(EngineManagement::<NoIo>::check_binding(&request, &reply).is_err());
        reply["run"] = serde_json::json!(b.run);
        reply["server_power_changed"] = serde_json::json!(true);
        assert!(EngineManagement::<NoIo>::check_binding(&request, &reply).is_err());
    }

    #[test]
    fn cleanup_requires_exact_native_identity_not_a_missing_pid_or_different_boot() {
        let o = observation();
        let mut reply = serde_json::json!({"state":"ended","run":o.binding.run,"execution":o.binding.execution,
            "binding":o.binding,"server_power_changed":false,"proof_source":"native_supervisor",
            "proof":{"process":o.process,"sandbox":o.binding.execution,"job_processes":1}});
        assert_eq!(
            confirmed_remote_end(o.binding.run, Some(&o), &reply).unwrap(),
            o.process
        );
        reply["proof"]["process"]["start_time_ticks"] = serde_json::json!(124);
        assert!(confirmed_remote_end(o.binding.run, Some(&o), &reply).is_err());
        reply["proof"]["process"] = serde_json::json!(o.process);
        reply["proof"]["job_processes"] = serde_json::json!(0);
        assert!(confirmed_remote_end(o.binding.run, Some(&o), &reply).is_err());
        reply["proof"]["job_processes"] = serde_json::json!(1);
        reply["binding"]["boot"] = serde_json::json!(2);
        assert!(confirmed_remote_end(o.binding.run, Some(&o), &reply).is_err());
        reply["binding"] = serde_json::Value::Null;
        assert!(confirmed_remote_end(o.binding.run, None, &reply).is_ok());
        reply["proof_source"] = serde_json::json!("pid_missing");
        assert!(confirmed_remote_end(o.binding.run, None, &reply).is_err());
    }

    #[test]
    fn remote_reports_cannot_be_reused_or_waited_into_fresh_evidence() {
        let clock = Arc::new(ManualClock::new(MonotonicTime::ZERO));
        let o = observation();
        let runtime = RuntimeSubject {
            category: ExecutionCategory::VmSandbox,
            release: BackendRelease::new(Backend::Qemu, "11.0.3").unwrap(),
            instance: o.binding.workload_identity(),
        };
        let subject = Subject::Runtime(runtime.clone());
        let probe = || RemoteObservationProbe {
            runtime: runtime.clone(),
            configuration: o.configuration,
            clock: Arc::clone(&clock),
            started: MonotonicTime::ZERO,
            consumed: AtomicBool::new(false),
        };
        let first = probe();
        let one = first.observe(&subject);
        assert_eq!(first.source(), SourceClass::ProviderApi);
        let two = first.observe(&subject);
        assert_ne!(one, two);
        clock.advance(Duration::from_secs(4));
        assert_eq!(probe().observe(&subject), two);
    }
}
