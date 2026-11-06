//! The engine's side of the lifetime supervisor (module docs in `supervisor`): which VMs it
//! holds, its start on first need and again after its death, the heartbeat with the lease
//! terms at every poll, the release of every VM that ended, and the journals of earlier
//! supervisors read at the engine's start. The engine's ledger and lifecycle stay the only
//! owners of capacity, authority and revocation; this hands the supervisor handles and
//! terms and turns what it reports into revocations and audit records.

use std::collections::{BTreeSet, VecDeque};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use crate::foundation::events::{Field, FieldValue};
use crate::foundation::ids::{digest, ExecutionId};
use crate::foundation::process::ProcessIdentity;
use crate::sandbox::lifecycle::{LimitKind, RevocationCause};
use crate::sandbox::vm_service::{LeaseTerms, SandboxId, VmService};

use super::ports::ProductionPorts;
use super::supervisor::journal::{self, JournalEvent, ReadJournal};
use super::supervisor::protocol::{SandboxTerms, Terms};
use super::supervisor::{EndCause, HeldEnd, SupervisorClient, SupervisorSettings};

type Service = VmService<ProductionPorts>;

/// How long a supervisor may take to start and answer its hello.
const START_WITHIN: Duration = Duration::from_secs(30);

/// How long the engine's start waits for an earlier engine's supervisor to finish ending
/// that engine's task VMs before it reads its journal.
const EARLIER_WAIT: Duration = Duration::from_secs(15);

/// The most reported ends kept for the status.
const MAX_REPORTED: usize = 32;

/// The production settings: an engine silent for two minutes counts as failed (VM-D7);
/// a lease limit gets thirty seconds of grace for the engine's own revocation; a kill round
/// waits five seconds. Acceptance builds may shorten the first two for a run
/// (`YOUGORI_ACCEPTANCE_SUPERVISOR_SILENCE_SECONDS`, `_GRACE_SECONDS`).
pub(super) fn settings() -> SupervisorSettings {
    let settings = SupervisorSettings {
        silence_ms: 120_000,
        grace_ms: 30_000,
        kill_wait_ms: 5_000,
    };
    #[cfg(feature = "acceptance")]
    let settings = acceptance_settings(settings);
    settings
}

/// An acceptance run's shorter silence and grace, from its environment.
#[cfg(feature = "acceptance")]
fn acceptance_settings(mut settings: SupervisorSettings) -> SupervisorSettings {
    let seconds = |name: &str| {
        std::env::var(name)
            .ok()
            .and_then(|text| text.parse::<u64>().ok())
            .filter(|seconds| *seconds > 0)
    };
    if let Some(silence) = seconds("YOUGORI_ACCEPTANCE_SUPERVISOR_SILENCE_SECONDS") {
        settings.silence_ms = silence * 1000;
    }
    if let Some(grace) = seconds("YOUGORI_ACCEPTANCE_SUPERVISOR_GRACE_SECONDS") {
        settings.grace_ms = grace * 1000;
    }
    settings
}

fn millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

fn terms_of(terms: &LeaseTerms) -> Terms {
    Terms {
        idle_left_ms: millis(terms.idle_left),
        absolute_left_ms: terms.absolute_left.map(millis),
        renewal_left_ms: terms.renewal_left.map(millis),
        delegation_deadline_host_ns: terms.delegation_deadline_host_ns,
    }
}

/// The revocation an end under the supervisor stands for; `None` for an end the service
/// observes as its own (the engine stopped the VM, or it ended itself) or one only an
/// earlier engine's journal tells of.
pub(super) fn revocation_cause(cause: EndCause) -> Option<RevocationCause> {
    match cause {
        EndCause::EngineSilent => Some(RevocationCause::EngineDied),
        EndCause::IdleLimit => Some(RevocationCause::LeaseExpired {
            kind: LimitKind::Idle,
        }),
        EndCause::AbsoluteLimit => Some(RevocationCause::LeaseExpired {
            kind: LimitKind::Absolute,
        }),
        EndCause::RenewalLimit => Some(RevocationCause::LeaseExpired {
            kind: LimitKind::ServiceRenewal,
        }),
        EndCause::EngineDied | EndCause::EndedWithoutSupervisor => None,
    }
}

/// The digest a supervisor is named by in audit records (the stream redacts token-like
/// text, and a PID alone is reused).
fn supervisor_reference(supervisor: &ProcessIdentity) -> FieldValue {
    FieldValue::Digest(digest(
        "yougori/audit/sandbox-supervisor/v1",
        &[
            &supervisor.pid.to_le_bytes(),
            &supervisor.start_time_ticks.to_le_bytes(),
        ],
    ))
}

/// The audit fields of an end the supervisor observed (a `TerminationReceipt` in the
/// sandbox's stream): its cause, how long after the cause it acted, what the host saw, and
/// which supervisor, by digest.
pub(super) fn end_fields(
    end: &HeldEnd,
    supervisor: Option<&ProcessIdentity>,
    source: &str,
) -> Vec<Field> {
    let mut fields = vec![
        Field::metadata("action", "vm_lifetime_end"),
        Field::metadata("observer", "lifetime_supervisor"),
        Field::metadata("source", source.to_owned()),
        Field::metadata(
            "cause",
            serde_json::to_value(end.cause)
                .ok()
                .and_then(|value| value.as_str().map(str::to_owned))
                .unwrap_or_default(),
        ),
        Field::metadata(
            "execution",
            FieldValue::Digest(crate::sandbox_contract::files::execution_reference(
                &end.sandbox,
            )),
        ),
        Field::metadata("kill_rounds", u64::from(end.kill_rounds)),
        Field::metadata("ended_within_ms", end.ended_within_ms),
    ];
    if let Some(code) = end.exit_code {
        fields.push(Field::metadata("exit_code", u64::from(code)));
    }
    if let Some(after) = end.decided_after_ms {
        fields.push(Field::metadata("decided_after_ms", after));
    }
    if let Some(supervisor) = supervisor {
        fields.push(Field::metadata(
            "supervisor",
            supervisor_reference(supervisor),
        ));
    }
    fields
}

/// The engine's side of the supervisor (module notes).
pub(super) struct Lifetimes {
    client: Option<SupervisorClient>,
    /// The sandboxes the supervisor holds, as far as the engine knows.
    held: BTreeSet<ExecutionId>,
    dir: PathBuf,
    settings: SupervisorSettings,
    starts: u64,
    /// Supervisors of this run that ended or were replaced, and how.
    replaced: Vec<Value>,
    /// The latest ends the supervisor reported.
    reported: VecDeque<Value>,
    last_error: Option<String>,
    last_heartbeat: Option<Instant>,
    confirmed_updates: u64,
    unended: BTreeSet<ExecutionId>,
}

impl Lifetimes {
    pub(super) fn new(dir: PathBuf, settings: SupervisorSettings) -> Self {
        Self {
            client: None,
            held: BTreeSet::new(),
            dir,
            settings,
            starts: 0,
            replaced: Vec::new(),
            reported: VecDeque::new(),
            last_error: None,
            last_heartbeat: None,
            confirmed_updates: 0,
            unended: BTreeSet::new(),
        }
    }

    /// The supervisor that holds the VMs, if it runs.
    pub(super) fn identity(&self) -> Option<ProcessIdentity> {
        self.client.as_ref().map(SupervisorClient::identity)
    }

    /// A live supervisor: the current one, or a new one after its death or failure, which
    /// is handed every VM the last one held again (each VM kept running meanwhile: the
    /// engine holds its own handles).
    fn ensure(&mut self, service: &Service) -> Result<&mut SupervisorClient, String> {
        if self.client.as_ref().is_some_and(SupervisorClient::alive) {
            if self
                .client
                .as_ref()
                .is_some_and(|client| !client.can_control())
            {
                return Err("The supervisor's channel ended; its held VMs must end before another supervisor can replace it.".to_owned());
            }
            return self
                .client
                .as_mut()
                .ok_or_else(|| "the supervisor vanished".to_owned());
        }
        if let Some(old) = self.client.take() {
            self.replaced.push(json!({
                "supervisor": old.identity(),
                "end": "ended",
                "holding": self.held.len(),
            }));
        }
        let executable = std::env::current_exe()
            .map_err(|error| format!("the engine's executable is unknown: {error}"))?;
        let client = SupervisorClient::start(&executable, &self.dir, self.settings, START_WITHIN)?;
        self.starts += 1;
        let client = self.client.insert(client);
        let terms: Vec<LeaseTerms> = service.lease_terms();
        let mut lost = Vec::new();
        for sandbox in self.held.clone() {
            let id = SandboxId::new(sandbox.clone());
            let handed = service.share_vm(&id, client.process()).and_then(|vm| {
                let terms = terms
                    .iter()
                    .find(|terms| terms.sandbox == id)
                    .map(terms_of)
                    .unwrap_or_default();
                client.hold(&vm, terms)
            });
            if let Err(error) = handed {
                lost.push(json!({ "sandbox": sandbox, "error": error }));
                self.held.remove(&sandbox);
            }
        }
        if !lost.is_empty() {
            self.last_error = Some(format!(
                "the new supervisor could not hold every VM again: {lost:?}"
            ));
        }
        Ok(client)
    }

    /// Hands `sandbox`'s VM to the supervisor, starting it on first need.
    pub(super) fn hold(&mut self, service: &Service, sandbox: &SandboxId) -> Result<Value, String> {
        let client = self.ensure(service)?;
        let vm = service.share_vm(sandbox, client.process())?;
        let terms = service
            .lease_terms()
            .iter()
            .find(|terms| &terms.sandbox == sandbox)
            .map(terms_of)
            .unwrap_or_default();
        let holding = match client.hold(&vm, terms) {
            Ok(holding) => holding,
            Err(error) => {
                // It may already hold these handles, and remains the independent
                // deadline guard of other VMs. A transport timeout is not proof
                // that it died. The caller refuses/stops this new VM; never kill
                // the existing guard before its held processes have ended.
                self.last_error = Some(error.clone());
                return Err(error);
            }
        };
        self.held.insert(sandbox.execution().clone());
        Ok(json!({
            "supervisor": self.identity(),
            "process": vm.process,
            "class": vm.class,
            "holding": holding,
            "terms": terms,
        }))
    }

    /// Lets `sandbox`'s VM go (the engine stopped it); what the supervisor said.
    pub(super) fn release(&mut self, sandbox: &SandboxId) -> Option<Value> {
        if !self.held.remove(sandbox.execution()) {
            return None;
        }
        let client = self.client.as_mut().filter(|client| client.alive())?;
        Some(match client.release(sandbox.execution()) {
            Ok(end) => json!({ "released": true, "end": end }),
            Err(error) => json!({ "released": false, "error": error }),
        })
    }

    /// The heartbeat (module notes): a live supervisor (restarted after its death), the
    /// VMs that ended without it let go, the lease terms of the rest sent; the ends the
    /// supervisor reported, for the engine to revoke and audit.
    pub(super) fn supervise(
        &mut self,
        service: &Service,
    ) -> Vec<(HeldEnd, Option<ProcessIdentity>)> {
        if self.held.is_empty() && self.client.is_none() {
            return Vec::new();
        }
        // A VM whose process the service no longer holds ended: it needs no holder.
        let statuses = service.status();
        let gone: Vec<ExecutionId> = self
            .held
            .iter()
            .filter(|sandbox| {
                !statuses.iter().any(|status| {
                    status.sandbox.execution() == *sandbox && status.process.is_some()
                })
            })
            .cloned()
            .collect();
        for sandbox in gone {
            let _ = self.release(&SandboxId::new(sandbox));
        }
        let all_terms = service.lease_terms();
        let terms: Vec<SandboxTerms> = all_terms
            .iter()
            .filter(|terms| self.held.contains(terms.sandbox.execution()))
            .map(|terms| SandboxTerms {
                sandbox: terms.sandbox.execution().clone(),
                terms: terms_of(terms),
            })
            .collect();
        let client = match self.ensure(service) {
            Ok(client) => client,
            Err(error) => {
                self.last_error = Some(error);
                return Vec::new();
            }
        };
        let identity = client.identity();
        match client.leases(terms) {
            Ok((ended, _holding, unended)) => {
                self.last_heartbeat = Some(Instant::now());
                self.confirmed_updates = self.confirmed_updates.wrapping_add(1);
                self.unended = unended.into_iter().collect();
                for end in &ended {
                    self.held.remove(&end.sandbox);
                    self.reported
                        .push_back(json!({ "supervisor": identity, "end": end }));
                    while self.reported.len() > MAX_REPORTED {
                        self.reported.pop_front();
                    }
                }
                ended.into_iter().map(|end| (end, Some(identity))).collect()
            }
            Err(error) => {
                // Retain the independent guard and its last deadlines when IPC
                // fails. Killing a live guard would open an enforcement gap if
                // the engine then paused. Only observed death permits ensure()
                // to replace it; a lost channel may require ending held VMs.
                self.last_error = Some(error);
                Vec::new()
            }
        }
    }

    /// A control grant cannot become usable before an acknowledged deadline
    /// update of this exact held VM. Return observed ends for the ordinary audit
    /// and revocation path even when this VM's confirmation fails.
    pub(super) fn confirm_remote_bound(
        &mut self,
        service: &Service,
        sandbox: &SandboxId,
    ) -> (Result<(), String>, Vec<(HeldEnd, Option<ProcessIdentity>)>) {
        let before = self.confirmed_updates;
        let ends = self.supervise(service);
        let confirmed = self.confirmed_updates != before
            && self.held.contains(sandbox.execution())
            && !self.unended.contains(sandbox.execution());
        let result = if confirmed {
            Ok(())
        } else {
            Err(
                "The independent supervisor did not confirm the remote VM's delegation deadline."
                    .to_owned(),
            )
        };
        (result, ends)
    }

    /// What the status shows of the supervisor.
    pub(super) fn view(&self) -> Value {
        let client = self.client.as_ref();
        json!({
            "running": client.is_some_and(SupervisorClient::alive),
            "control_connected": client.is_some_and(SupervisorClient::can_control),
            "supervisor": client.map(SupervisorClient::identity),
            "settings": self.settings,
            "starts": self.starts,
            "held": self.held,
            "replaced": self.replaced,
            "reported_ends": self.reported,
            "last_error": self.last_error,
            "heartbeat_age_ms": self.last_heartbeat.map(|at| millis(at.elapsed())),
            "job_usage": client.and_then(SupervisorClient::usage),
            "restrictions": client.map(|client| client.restrictions().unwrap_or_else(|error| json!({ "error": error }))),
        })
    }
}

/// What earlier engines' supervisors left: their journals, read once each has ended, and
/// those still running after a bounded wait (they hold a VM still).
pub(super) struct EarlierSupervisors {
    pub read: Vec<ReadJournal>,
    pub still_running: Vec<String>,
}

/// Waits at most [`EARLIER_WAIT`] for every earlier supervisor to end (one ends once the
/// engine that started it died and its task VMs ended), reading each journal as its
/// supervisor ends.
pub(super) fn earlier_supervisors(dir: &Path) -> EarlierSupervisors {
    // Exited means not running, even while some handle keeps its process object.
    let running = |supervisor: &ProcessIdentity| supervisor.running().unwrap_or(false);
    let started = Instant::now();
    let mut read = Vec::new();
    loop {
        let (mut finished, still_running) = journal::take_finished(dir, running);
        read.append(&mut finished);
        if still_running.is_empty() || started.elapsed() >= EARLIER_WAIT {
            return EarlierSupervisors {
                read,
                still_running,
            };
        }
        std::thread::sleep(Duration::from_millis(250));
    }
}

/// The summary of earlier supervisors for the status, and each end their journals record
/// with its supervisor, for the audit stream.
pub(super) fn summarize(
    earlier: &EarlierSupervisors,
) -> (Value, Vec<(HeldEnd, Option<ProcessIdentity>)>) {
    let mut ends = Vec::new();
    let journals: Vec<Value> = earlier
        .read
        .iter()
        .map(|journal| {
            let mut engine_died = false;
            let mut exit = None;
            let mut held = 0;
            let mut ended = Vec::new();
            // An end a live engine received is in its own audit records already.
            let reported: BTreeSet<&ExecutionId> = journal
                .lines
                .iter()
                .filter_map(|line| match &line.event {
                    JournalEvent::Reported { sandboxes } => Some(sandboxes.iter()),
                    _ => None,
                })
                .flatten()
                .collect();
            for line in &journal.lines {
                match &line.event {
                    JournalEvent::EngineDied => engine_died = true,
                    JournalEvent::Exit { reason } => exit = Some(reason.clone()),
                    JournalEvent::Held { .. } => held += 1,
                    JournalEvent::Ended { end } => {
                        let reported_live = reported.contains(&end.sandbox);
                        if !reported_live {
                            ends.push((end.clone(), journal.supervisor));
                        }
                        ended.push(json!({
                            "sandbox": end.sandbox,
                            "cause": end.cause,
                            "decided_after_ms": end.decided_after_ms,
                            "ended_within_ms": end.ended_within_ms,
                            "kill_rounds": end.kill_rounds,
                            "reported_live": reported_live,
                        }));
                    }
                    _ => {}
                }
            }
            json!({
                "journal": journal.file,
                "supervisor": journal.supervisor,
                "held": held,
                "engine_died": engine_died,
                "ended": ended,
                "exit": exit,
                "unreadable_lines": journal.unreadable,
            })
        })
        .collect();
    (
        json!({ "journals": journals, "still_running": earlier.still_running }),
        ends,
    )
}
