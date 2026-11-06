//! The lifetime supervisor process (module docs in `mod.rs`): the engine binary started by
//! the engine as `--sandbox-supervisor PIPE ENGINE_PID JOURNAL_DIR`, restricted as the
//! executor is, in a job of its own whose handle it holds itself. It connects to the
//! engine's control pipe, admits only the engine named by PID through PX1 identity, takes
//! the handles the engine's hello and holds name after checking them, and then, every tick,
//! applies the rules of `policy` and writes what happened to its journal. It ends when the
//! engine says `Shutdown`, or once the engine has died and no VM is left to hold.

use std::path::PathBuf;
use std::time::Duration;

use crate::foundation::ids::{Clock, ExecutionId, MonotonicTime, SystemClock};
use crate::foundation::process::{AdoptedLifetime, AdoptedProcess, OwnJob, ProcessIdentity};
use crate::sandbox_contract::relay_link::control_pipe::ControlPipe;
use crate::sandbox_contract::relay_link::RelayPipeName;

use super::journal::{Journal, JournalEvent};
use super::policy::{EngineChange, Supervision};
use super::protocol::{
    decode_line, encode_line, SupervisorReply, SupervisorRequest, PROTOCOL_VERSION,
};

/// How long the supervisor waits for the engine's control pipe and its hello.
pub const CONNECT_WITHIN: Duration = Duration::from_secs(30);

/// One wait for a request; between waits the rules are applied.
pub const TICK: Duration = Duration::from_millis(250);

/// How long one reply may take to reach the engine.
pub const SEND_WITHIN: Duration = Duration::from_secs(10);

/// Exit codes beyond 0 (an orderly end).
pub const EXIT_ARGUMENTS: i32 = 30;
pub const EXIT_CONNECT: i32 = 31;
pub const EXIT_HELLO: i32 = 32;

/// Runs above normal priority, so its ticks run while ordinary work keeps every CPU busy
/// (CORE-03's supervisor reserve covers its memory; its job bounds it).
#[cfg(windows)]
fn raise_priority() {
    use windows_sys::Win32::System::Threading::{
        GetCurrentProcess, SetPriorityClass, ABOVE_NORMAL_PRIORITY_CLASS,
    };
    // SAFETY: the pseudo-handle of this process, which may always set its own class.
    unsafe {
        SetPriorityClass(GetCurrentProcess(), ABOVE_NORMAL_PRIORITY_CLASS);
    }
}

/// On Linux the engine started it at a nice value of -5 (`client::supervisor_group`): it
/// holds no capability to raise its own priority.
#[cfg(target_os = "linux")]
fn raise_priority() {}

fn send(pipe: &mut ControlPipe, reply: &SupervisorReply) -> bool {
    match encode_line(reply) {
        Ok(line) => pipe.send_line(&line, SEND_WITHIN).is_ok(),
        Err(_) => false,
    }
}

/// Runs this process as the lifetime supervisor; `arguments` follow the mode word.
pub fn run_supervisor(arguments: &[String]) -> i32 {
    let (name, engine_pid, journal_dir) = match arguments {
        [name, pid, dir] => match (RelayPipeName::new(name.clone()), pid.parse::<u32>()) {
            (Ok(name), Ok(pid)) => (name, pid, PathBuf::from(dir)),
            _ => return EXIT_ARGUMENTS,
        },
        _ => return EXIT_ARGUMENTS,
    };
    let engine = match ProcessIdentity::holder_of(engine_pid) {
        Ok(Some(engine)) => engine,
        _ => return EXIT_CONNECT,
    };
    let mut pipe = match ControlPipe::connect(&name, &engine, CONNECT_WITHIN) {
        Ok(pipe) => pipe,
        Err(_) => return EXIT_CONNECT,
    };
    raise_priority();
    let Ok(Some(line)) = pipe.read_line(CONNECT_WITHIN) else {
        return EXIT_HELLO;
    };
    let (engine_process, _own_job, settings) = match decode_line(&line) {
        Ok(SupervisorRequest::Hello {
            version,
            engine: named,
            engine_handle,
            own_job_handle,
            settings,
        }) if version == PROTOCOL_VERSION && named == engine => {
            // SAFETY: the engine admitted on this pipe duplicated both values into this
            // process for it; each is checked before it is taken.
            let taken = unsafe {
                AdoptedProcess::adopt(engine_handle, engine)
                    .and_then(|process| Ok((process, OwnJob::adopt(own_job_handle)?)))
            };
            match taken {
                Ok((process, job)) => (process, job, settings),
                Err(refusal) => {
                    send(
                        &mut pipe,
                        &SupervisorReply::Refused {
                            detail: refusal.to_string(),
                        },
                    );
                    return EXIT_HELLO;
                }
            }
        }
        Ok(_) => {
            send(
                &mut pipe,
                &SupervisorReply::Refused {
                    detail: "the first request must be a hello of this protocol from the engine"
                        .to_owned(),
                },
            );
            return EXIT_HELLO;
        }
        Err(_) => return EXIT_HELLO,
    };
    let Ok(Some(me)) = ProcessIdentity::holder_of(std::process::id()) else {
        return EXIT_HELLO;
    };
    let mut journal = Journal::create(&journal_dir, me);
    journal.record(JournalEvent::Started {
        supervisor: me,
        engine,
        settings,
    });
    if !send(
        &mut pipe,
        &SupervisorReply::Hello {
            version: PROTOCOL_VERSION,
            supervisor: me,
        },
    ) {
        journal.record(JournalEvent::Exit {
            reason: "the hello could not be answered".to_owned(),
        });
        return EXIT_HELLO;
    }
    let code = serve(pipe, engine_process, settings, journal);
    // On Linux its group outlives it otherwise (the engine that made it is gone by now):
    // it leaves the group and removes it; a group left behind is removed at the next start.
    #[cfg(target_os = "linux")]
    let _ = crate::foundation::process::leave_own_group();
    code
}

/// The supervisor's loop (module notes).
fn serve(
    mut pipe: ControlPipe,
    engine: AdoptedProcess,
    settings: super::protocol::SupervisorSettings,
    mut journal: Journal,
) -> i32 {
    let clock = SystemClock::new();
    let mut supervision: Supervision<AdoptedLifetime> = Supervision::new(settings, clock.now());
    let mut pipe_open = true;
    let mut reported_unended = std::collections::BTreeSet::new();
    loop {
        if pipe_open {
            match pipe.read_line(TICK) {
                Ok(Some(line)) => {
                    let now = clock.now();
                    // Enforce elapsed authority before a queued heartbeat or renewal.
                    enforce(
                        &mut supervision,
                        &mut journal,
                        &mut reported_unended,
                        now,
                        !engine.ended(),
                    );
                    if let Some(change) = supervision.heard(now) {
                        record_change(&mut journal, change);
                    }
                    let (reply, shutdown) = answer(&mut supervision, &mut journal, &line, now);
                    if !send(&mut pipe, &reply) {
                        pipe_open = false;
                    } else if let SupervisorReply::Leases { ended, .. } = &reply {
                        if !ended.is_empty() {
                            journal.record(JournalEvent::Reported {
                                sandboxes: ended.iter().map(|end| end.sandbox.clone()).collect(),
                            });
                        }
                    }
                    if shutdown {
                        journal.record(JournalEvent::Exit {
                            reason: "the engine shut down in order".to_owned(),
                        });
                        return 0;
                    }
                }
                Ok(None) => {}
                // The engine closed the pipe or died: the rules go on without it.
                Err(_) => pipe_open = false,
            }
        } else {
            std::thread::sleep(TICK);
        }
        enforce(
            &mut supervision,
            &mut journal,
            &mut reported_unended,
            clock.now(),
            !engine.ended(),
        );
        if supervision.finished() {
            journal.record(JournalEvent::Exit {
                reason: "the engine ended and no VM is left to hold".to_owned(),
            });
            return 0;
        }
        if !pipe_open && supervision.holding() == 0 {
            journal.record(JournalEvent::Exit {
                reason: "the engine closed the control pipe and no VM is held".to_owned(),
            });
            return 0;
        }
    }
}

fn enforce(
    supervision: &mut Supervision<AdoptedLifetime>,
    journal: &mut Journal,
    reported_unended: &mut std::collections::BTreeSet<ExecutionId>,
    now: MonotonicTime,
    engine_alive: bool,
) {
    let (changes, ends) = supervision.tick(now, engine_alive);
    for change in changes {
        record_change(journal, change);
    }
    for end in ends {
        reported_unended.remove(&end.sandbox);
        journal.record(JournalEvent::Ended { end });
    }
    for sandbox in supervision.unended() {
        if reported_unended.insert(sandbox.clone()) {
            journal.record(JournalEvent::KillUnproven {
                    sandbox,
                    detail: "the host did not observe the end within the kill rounds; trying again each tick".to_owned(),
                });
        }
    }
}

fn record_change(journal: &mut Journal, change: EngineChange) {
    let millis = |duration: Duration| u64::try_from(duration.as_millis()).unwrap_or(u64::MAX);
    journal.record(match change {
        EngineChange::Died => JournalEvent::EngineDied,
        EngineChange::Silent { quiet_for } => JournalEvent::EngineSilent {
            quiet_for_ms: millis(quiet_for),
        },
        EngineChange::AnsweringAgain => JournalEvent::EngineAnsweringAgain,
        EngineChange::Gap { gap } => JournalEvent::Gap {
            gap_ms: millis(gap),
        },
    });
}

/// The reply to one request line, and whether it was the shutdown.
fn answer(
    supervision: &mut Supervision<AdoptedLifetime>,
    journal: &mut Journal,
    line: &[u8],
    now: MonotonicTime,
) -> (SupervisorReply, bool) {
    let refused = |detail: String| (SupervisorReply::Refused { detail }, false);
    let request = match decode_line::<SupervisorRequest>(line) {
        Ok(request) => request,
        Err(error) => return refused(format!("the request does not read: {error}")),
    };
    match request {
        SupervisorRequest::Hello { .. } => refused("the hello was taken already".to_owned()),
        SupervisorRequest::Hold {
            sandbox,
            class,
            process,
            handles,
            terms,
        } => {
            // SAFETY: the engine admitted on this pipe duplicated both values into this
            // process for this hold; they are checked to be `process` and its job before
            // they are taken, and a refusal takes nothing.
            let lifetime = match unsafe { AdoptedLifetime::adopt(handles, process) } {
                Ok(lifetime) => lifetime,
                Err(refusal) => {
                    let detail = refusal.to_string();
                    let reply = SupervisorReply::HoldRefused {
                        sandbox,
                        detail,
                        taken: false,
                    };
                    return (reply, false);
                }
            };
            match supervision.hold(sandbox.clone(), class, lifetime, terms, now) {
                Ok(holding) => {
                    journal.record(JournalEvent::Held {
                        sandbox: sandbox.clone(),
                        class,
                        process,
                    });
                    (SupervisorReply::Held { sandbox, holding }, false)
                }
                Err(detail) => (
                    SupervisorReply::HoldRefused {
                        sandbox,
                        detail,
                        taken: true,
                    },
                    false,
                ),
            }
        }
        SupervisorRequest::Leases { terms } => {
            supervision.leases(&terms, now);
            (
                SupervisorReply::Leases {
                    ended: supervision.take_ends(),
                    holding: supervision.holding(),
                    unended: supervision.unended(),
                },
                false,
            )
        }
        SupervisorRequest::Release { sandbox } => {
            let end = supervision.release(&sandbox, now);
            journal.record(JournalEvent::Released {
                sandbox: sandbox.clone(),
            });
            (SupervisorReply::Released { sandbox, end }, false)
        }
        SupervisorRequest::Shutdown {} => (
            SupervisorReply::Bye {
                released: supervision.release_all(),
            },
            true,
        ),
    }
}
