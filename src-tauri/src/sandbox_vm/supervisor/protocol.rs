//! The control protocol between the engine and its lifetime supervisor (module docs in
//! `mod.rs`): one JSON line per message over the control pipe, strict on both sides, each
//! request answered by exactly one reply in order. No guest byte, credential or PID-addressed
//! action crosses it: a VM is named by its sandbox and acted on only through the handles the
//! engine duplicated into the supervisor, which the supervisor checks against the identity
//! named beside them.

use serde::{Deserialize, Serialize};

use crate::foundation::ids::ExecutionId;
use crate::foundation::process::{LifetimeEnded, ProcessIdentity, SharedHandles};
use crate::sandbox::lifecycle::SandboxClass;

/// The protocol version both ends must speak.
pub const PROTOCOL_VERSION: u32 = 2;

/// The longest line either side accepts.
pub const MAX_LINE_BYTES: usize = 64 * 1024;

/// The most VMs one supervisor holds; a hold beyond it is refused.
pub const MAX_HELD: usize = 64;

/// The most ends one reply carries; the rest wait for the next reply.
pub const MAX_ENDS_PER_REPLY: usize = 64;

/// How the supervisor applies VM-D7 and the lease backstop, set by the engine at the hello.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SupervisorSettings {
    /// How long the engine may go without a request before the supervisor counts it as
    /// failed: task sandboxes end with a failed engine (VM-D7).
    pub silence_ms: u64,
    /// How long past one of a sandbox's lease limits the supervisor leaves the engine to
    /// revoke it before it ends the VM itself.
    pub grace_ms: u64,
    /// How long each kill round waits for the end to be observed.
    pub kill_wait_ms: u64,
}

/// What is left of one sandbox's lease limits when the engine said so, in milliseconds;
/// `None` for a limit its class does not have.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Terms {
    pub idle_left_ms: u64,
    pub absolute_left_ms: Option<u64>,
    pub renewal_left_ms: Option<u64>,
    /// Absolute elapsed nanoseconds in this host boot, with NO grace. This is
    /// only exchanged over the engine/supervisor's authenticated local pipe.
    /// A queued message cannot rebase a remote delegation at its arrival time.
    pub delegation_deadline_host_ns: Option<u64>,
}

/// One held sandbox's terms.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SandboxTerms {
    pub sandbox: ExecutionId,
    pub terms: Terms,
}

/// A request from the engine.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "request", rename_all = "snake_case", deny_unknown_fields)]
pub enum SupervisorRequest {
    /// The first request: the version, the engine's identity and a handle to its process
    /// (synchronize and limited query) duplicated into the supervisor, the supervisor's
    /// own job handle duplicated into it (so its job stays open after the engine's handle
    /// closes), and the settings.
    Hello {
        version: u32,
        engine: ProcessIdentity,
        engine_handle: u64,
        own_job_handle: u64,
        settings: SupervisorSettings,
    },
    /// Hold one sandbox's VM: its class (VM-D7), its host process and the job and process
    /// handles duplicated into the supervisor, and its lease terms now.
    Hold {
        sandbox: ExecutionId,
        class: SandboxClass,
        process: ProcessIdentity,
        handles: SharedHandles,
        terms: Terms,
    },
    /// The lease terms of the held sandboxes now; also the engine's heartbeat. Answered with
    /// the ends since the last reply.
    Leases { terms: Vec<SandboxTerms> },
    /// Let one sandbox go: the engine stopped its VM or is stopping it itself.
    Release { sandbox: ExecutionId },
    /// The engine stops in order: every VM is let go (the engine stopped them) and the
    /// supervisor ends. (A struct variant, so a field it does not have is refused.)
    Shutdown {},
}

/// Why a held VM ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EndCause {
    /// The VM ended without the supervisor (the engine stopped it, or it ended itself).
    EndedWithoutSupervisor,
    /// The engine died and the sandbox's class ends with it (VM-D7).
    EngineDied,
    /// The engine stopped answering for the silence bound: counted as failed (VM-D7).
    EngineSilent,
    /// A lease limit passed by the grace without the engine's revocation (§6.2).
    IdleLimit,
    AbsoluteLimit,
    RenewalLimit,
}

/// How a held VM ended, as the supervisor observed it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HeldEnd {
    pub sandbox: ExecutionId,
    pub process: ProcessIdentity,
    pub cause: EndCause,
    /// From the moment the cause arose (the engine's death or silence, the limit plus its
    /// grace) to the supervisor's first kill; `None` for an end without the supervisor.
    pub decided_after_ms: Option<u64>,
    /// The exit code the host observed; `None` where the host does not tell the supervisor
    /// (Linux before 6.15, for an end it did not cause).
    pub exit_code: Option<u32>,
    /// Every process the VM's job ever held.
    pub job_processes: u32,
    /// The supervisor's kill rounds; 0 when it ended without one.
    pub kill_rounds: u32,
    /// From the first kill (or the look) to the observed end.
    pub ended_within_ms: u64,
    /// The supervisor's running time when it observed the end.
    pub at_ms: u64,
}

impl HeldEnd {
    /// The end of `sandbox`'s VM `process` for `cause`, from what the host observed.
    pub fn observed(
        sandbox: ExecutionId,
        process: ProcessIdentity,
        cause: EndCause,
        decided_after_ms: Option<u64>,
        ended: LifetimeEnded,
        at_ms: u64,
    ) -> Self {
        Self {
            sandbox,
            process,
            cause,
            decided_after_ms,
            exit_code: ended.exit_code,
            job_processes: ended.job_processes,
            kill_rounds: ended.kill_rounds,
            ended_within_ms: u64::try_from(ended.elapsed.as_millis()).unwrap_or(u64::MAX),
            at_ms,
        }
    }
}

/// A reply from the supervisor.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "reply", rename_all = "snake_case", deny_unknown_fields)]
pub enum SupervisorReply {
    Hello {
        version: u32,
        supervisor: ProcessIdentity,
    },
    Held {
        sandbox: ExecutionId,
        holding: usize,
    },
    /// The hold was refused. `taken` says whether the supervisor took the handles (and
    /// closed them in dropping the hold): when not, they are still open in the supervisor
    /// for the engine to close.
    HoldRefused {
        sandbox: ExecutionId,
        detail: String,
        taken: bool,
    },
    /// The ends since the last reply (at most [`MAX_ENDS_PER_REPLY`]), and the VMs held.
    Leases {
        ended: Vec<HeldEnd>,
        holding: usize,
        /// VMs the supervisor tried to end and could not prove ended yet.
        unended: Vec<ExecutionId>,
    },
    /// The sandbox let go; its end when the supervisor saw the VM end first.
    Released {
        sandbox: ExecutionId,
        end: Option<HeldEnd>,
    },
    Bye {
        released: usize,
    },
    Refused {
        detail: String,
    },
}

/// One message as its line, newline included; refused past [`MAX_LINE_BYTES`].
pub fn encode_line<T: Serialize>(message: &T) -> Result<Vec<u8>, String> {
    let mut line = serde_json::to_vec(message).map_err(|error| error.to_string())?;
    line.push(b'\n');
    if line.len() > MAX_LINE_BYTES {
        return Err(format!(
            "the message is {} bytes, over the line bound",
            line.len()
        ));
    }
    Ok(line)
}

/// One line, without its newline, as a message; strict.
pub fn decode_line<T: for<'de> Deserialize<'de>>(line: &[u8]) -> Result<T, String> {
    if line.len() > MAX_LINE_BYTES {
        return Err("the line is over the bound".to_owned());
    }
    serde_json::from_slice(line).map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity(pid: u32) -> ProcessIdentity {
        ProcessIdentity {
            pid,
            start_time_ticks: 7,
        }
    }

    /// PROVES every request and reply round-trips and an unknown field, request or a line
    /// past the bound is refused, so neither end acts on a message it does not fully read.
    #[test]
    fn messages_round_trip_and_anything_else_is_refused() {
        let sandbox = ExecutionId::new("exe-a").unwrap();
        let requests = vec![
            SupervisorRequest::Hello {
                version: PROTOCOL_VERSION,
                engine: identity(1),
                engine_handle: 4,
                own_job_handle: 8,
                settings: SupervisorSettings {
                    silence_ms: 1,
                    grace_ms: 2,
                    kill_wait_ms: 3,
                },
            },
            SupervisorRequest::Hold {
                sandbox: sandbox.clone(),
                class: SandboxClass::Task,
                process: identity(2),
                handles: SharedHandles {
                    job: 12,
                    process: 16,
                },
                terms: Terms {
                    idle_left_ms: 5,
                    absolute_left_ms: Some(6),
                    renewal_left_ms: None,
                    delegation_deadline_host_ns: Some(7),
                },
            },
            SupervisorRequest::Leases {
                terms: vec![SandboxTerms {
                    sandbox: sandbox.clone(),
                    terms: Terms::default(),
                }],
            },
            SupervisorRequest::Release {
                sandbox: sandbox.clone(),
            },
            SupervisorRequest::Shutdown {},
        ];
        for request in requests {
            let line = encode_line(&request).unwrap();
            let back: SupervisorRequest = decode_line(&line[..line.len() - 1]).unwrap();
            assert_eq!(back, request);
        }
        let end = HeldEnd {
            sandbox: sandbox.clone(),
            process: identity(2),
            cause: EndCause::EngineSilent,
            decided_after_ms: Some(10),
            exit_code: Some(1),
            job_processes: 1,
            kill_rounds: 1,
            ended_within_ms: 3,
            at_ms: 99,
        };
        let reply = SupervisorReply::Leases {
            ended: vec![end],
            holding: 0,
            unended: Vec::new(),
        };
        let line = encode_line(&reply).unwrap();
        assert_eq!(
            decode_line::<SupervisorReply>(&line[..line.len() - 1]).unwrap(),
            reply
        );
        assert!(decode_line::<SupervisorRequest>(br#"{"request":"shutdown","extra":1}"#).is_err());
        assert!(decode_line::<SupervisorRequest>(br#"{"request":"kill","pid":4}"#).is_err());
        assert!(decode_line::<SupervisorRequest>(&vec![b' '; MAX_LINE_BYTES + 1]).is_err());
        let long = SupervisorReply::Refused {
            detail: "x".repeat(MAX_LINE_BYTES),
        };
        assert!(encode_line(&long).is_err());
    }
}
