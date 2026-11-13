//! The doctor's VM-CP-29 connection drill (M08; §17 line 3179; module docs in
//! `sandbox::probes::drill`): `yougori sandbox drill vm-cp-29 --yes` launches three throwaway VM
//! sandboxes of its own, A, B and C, makes deliberate connection attempts between them under each
//! grant state the check names, and stops all three whatever happens; it never touches another
//! sandbox. B serves two declared services (`svc` and `other`), C one (`svc`), each a listener
//! answering one line (BusyBox `nc`); A's endpoints name B's two services and C's, B's names C's.
//!
//! The attempts, in order: A to B with no grant; A to B's `svc` under its grant; A to B's
//! `other`, while A holds the grant to `svc` only; A to C while A holds a grant to B and B one to
//! C (transitive); B to C under its grant, the transitive case's control; A to B after the grant
//! was withdrawn; A to B after a two-second grant expired. Each attempt is one connection a
//! program in the caller makes; it is judged from the host's counters alone: the connections the
//! gate refused and admitted for the caller, and the ingress streams the callee's link opened (its
//! guest asked to open the port). Whether the drill's VMs share host state is read from their
//! private directories. The observations go to the doctor, stamped on the service's evidence clock
//! under this host's configuration, and stay current for as long as the host's other
//! observations.

use std::collections::BTreeMap;
use std::sync::{Arc, Weak};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use super::{Production, CONFINEMENT_FRESH_FOR, LEAST_LAUNCH_MEMORY_BYTES, TENANT};
use crate::foundation::ids::TenantId;
use crate::sandbox::backend::HostObserved;
use crate::sandbox::probes::{ConnectionDrill, DrillAttempt, DrillCase};
use crate::sandbox::vm_service::{
    ConnectionEndpoint, ExecRequest, LaunchSpec, PublishedPort, SandboxId, VmResources,
};

/// The one check a drill exists for.
pub(super) const DRILL_CHECK: &str = "vm-cp-29";
/// The drill's services: B's and C's `svc`, and B's `other`.
const SERVICE_PORT: u16 = 7001;
const OTHER_PORT: u16 = 7002;
/// The ports the callers' programs use for each endpoint: never a service port of the same VM.
const TO_B: u16 = 7101;
const TO_B_OTHER: u16 = 7102;
const TO_C: u16 = 7103;
/// Each throwaway VM's reservation: the least a launch takes and a little room.
const DRILL_MEMORY_BYTES: u64 = LEAST_LAUNCH_MEMORY_BYTES + (64 << 20);
/// What one drill connection may carry each way.
const DRILL_BUDGET_BYTES: u64 = 1 << 20;
/// The drill's VMs end on their own soon after, should a stop fail.
const DRILL_IDLE: Duration = Duration::from_secs(10 * 60);
const DRILL_LIFETIME: Duration = Duration::from_secs(20 * 60);
/// The most drills kept for the doctor.
const KEPT_DRILLS: usize = 4;

fn published(service: &str, port: u16) -> PublishedPort {
    PublishedPort {
        service: service.to_owned(),
        port,
    }
}

fn endpoint(name: &str, port: u16) -> ConnectionEndpoint {
    ConnectionEndpoint {
        name: name.to_owned(),
        port,
    }
}

/// Whether two of `directories` are one, or one lies inside another; `None` when one is unknown.
fn shared(directories: &[Option<String>]) -> Option<bool> {
    let known: Vec<String> = directories
        .iter()
        .map(|directory| {
            directory
                .as_ref()
                .map(|path| path.trim_end_matches(['/', '\\']).to_ascii_lowercase())
        })
        .collect::<Option<_>>()?;
    let nested = |outer: &str, inner: &str| {
        inner == outer
            || inner
                .strip_prefix(outer)
                .is_some_and(|rest| rest.starts_with(['/', '\\']))
    };
    Some(known.iter().enumerate().any(|(i, one)| {
        known
            .iter()
            .enumerate()
            .any(|(j, other)| i != j && nested(one, other))
    }))
}

impl Production {
    /// Runs the VM-CP-29 drill (module docs): its report, and the host's observations kept for
    /// the doctor. Every VM it launched is stopped before it returns, and named in the report.
    /// `observe_capacity` observes the host's capacity again, as every launch needs a current
    /// reading.
    pub(super) fn drill_connections(
        self: &Arc<Self>,
        observe_capacity: &(dyn Fn() -> Result<(), String> + Send + Sync),
    ) -> Result<Value, String> {
        // Connections move through the gate's pump, the one previews use.
        let host: Weak<dyn super::super::preview::PreviewHost> = Arc::downgrade(self) as _;
        self.previews.start_pump(host);
        let mut launched = Vec::new();
        let result = self.drill_in(&mut launched, observe_capacity);
        let stopped: Vec<Value> = launched
            .iter()
            .map(|sandbox| match self.stop_sandbox(sandbox) {
                Ok(_) => json!({ "sandbox": sandbox, "stopped": true }),
                Err(error) => json!({ "sandbox": sandbox, "stopped": false, "error": error }),
            })
            .collect();
        match result {
            Ok(mut report) => {
                report["stopped"] = json!(stopped);
                Ok(report)
            }
            Err(error) => Err(format!(
                "The drill did not finish: {error} It launched and stopped: {}.",
                serde_json::to_string(&stopped).unwrap_or_default()
            )),
        }
    }

    fn drill_in(
        self: &Arc<Self>,
        launched: &mut Vec<SandboxId>,
        observe_capacity: &(dyn Fn() -> Result<(), String> + Send + Sync),
    ) -> Result<Value, String> {
        observe_capacity()?;
        let c = self.drill_launch(launched, vec![published("svc", SERVICE_PORT)], Vec::new())?;
        observe_capacity()?;
        let b = self.drill_launch(
            launched,
            vec![
                published("svc", SERVICE_PORT),
                published("other", OTHER_PORT),
            ],
            vec![endpoint("c", TO_C)],
        )?;
        observe_capacity()?;
        let a = self.drill_launch(
            launched,
            Vec::new(),
            vec![
                endpoint("b", TO_B),
                endpoint("b-other", TO_B_OTHER),
                endpoint("c", TO_C),
            ],
        )?;
        self.drill_listen(&b, &[SERVICE_PORT, OTHER_PORT])?;
        self.drill_listen(&c, &[SERVICE_PORT])?;
        let grant = |caller: &SandboxId, name: &str, callee: &SandboxId, lifetime: Duration| {
            self.service
                .connect(caller, name, callee, "svc", lifetime, DRILL_BUDGET_BYTES)
                .map(|_| ())
                .map_err(|error| format!("the drill's grant was refused: {error}."))
        };
        let minute = Duration::from_secs(60);
        let mut attempts = BTreeMap::new();
        attempts.insert(DrillCase::Ungranted, self.drill_attempt(&a, "b", TO_B, &b));
        grant(&a, "b", &b, minute)?;
        attempts.insert(DrillCase::Granted, self.drill_attempt(&a, "b", TO_B, &b));
        attempts.insert(
            DrillCase::OtherService,
            self.drill_attempt(&a, "b-other", TO_B_OTHER, &b),
        );
        grant(&b, "c", &c, minute)?;
        attempts.insert(DrillCase::Transitive, self.drill_attempt(&a, "c", TO_C, &c));
        attempts.insert(
            DrillCase::TransitiveControl,
            self.drill_attempt(&b, "c", TO_C, &c),
        );
        self.service
            .disconnect(&a, "b")
            .map_err(|error| format!("the drill's grant could not be withdrawn: {error}."))?;
        attempts.insert(DrillCase::Revoked, self.drill_attempt(&a, "b", TO_B, &b));
        grant(&a, "b", &b, Duration::from_secs(2))?;
        thread::sleep(Duration::from_secs(3));
        attempts.insert(DrillCase::Expired, self.drill_attempt(&a, "b", TO_B, &b));
        let directories: Vec<Option<String>> = [&a, &b, &c]
            .into_iter()
            .map(|sandbox| self.service.private_directory(sandbox))
            .collect();
        let drill = ConnectionDrill {
            attempts,
            shared_state: shared(&directories),
        };
        let now = self
            .service
            .clock_reading()
            .ok_or("the service's evidence clock could not be read.")?;
        {
            let mut drills = self
                .drills
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            drills.push(HostObserved::stamp(
                drill.clone(),
                now,
                CONFINEMENT_FRESH_FOR,
                self.configuration,
            ));
            let excess = drills.len().saturating_sub(KEPT_DRILLS);
            drills.drain(..excess);
        }
        let cases: Vec<Value> = drill
            .attempts
            .iter()
            .map(|(case, attempt)| {
                let judged = attempt.refused();
                json!({
                    "case": case,
                    "expected": if case.refusal_expected() { "refused" } else { "reached the callee" },
                    "host_observed": attempt,
                    "judged": match judged { Some(true) => "refused", Some(false) => "reached the callee", None => "no decision seen" },
                    "as_expected": judged == Some(case.refusal_expected()),
                })
            })
            .collect();
        let as_expected = cases.iter().all(|case| case["as_expected"] == json!(true))
            && drill.shared_state == Some(false);
        Ok(json!({
            "check": "VM-CP-29",
            "sandboxes": { "a": a, "b": b, "c": c },
            "cases": cases,
            "shared_state": drill.shared_state,
            "private_directories_distinct": drill.shared_state.map(|shared| !shared),
            "as_expected": as_expected,
            "doctor": format!("yougori doctor judges VM-CP-29 from these host observations for {} minutes.", CONFINEMENT_FRESH_FOR.as_secs() / 60),
        }))
    }

    fn drill_launch(
        &self,
        launched: &mut Vec<SandboxId>,
        published: Vec<PublishedPort>,
        connect: Vec<ConnectionEndpoint>,
    ) -> Result<SandboxId, String> {
        let spec = LaunchSpec {
            gpu: false,
            gpu_memory: Vec::new(),
            internet: false,
            targets: None,
            owner_session: false,
            tenant: TenantId::new(TENANT).map_err(|error| error.to_string())?,
            resources: VmResources {
                memory_bytes: DRILL_MEMORY_BYTES,
                cpu_slots: 1,
            },
            egress_endpoints: Vec::new(),
            workload_image: None,
            idle_limit: Some(DRILL_IDLE),
            lifetime_limit: Some(DRILL_LIFETIME),
            published,
            connect,
        };
        let (sandbox, _) = self.launch_with(spec, None, None)?;
        launched.push(sandbox.clone());
        Ok(sandbox)
    }

    /// Starts listeners on `ports` in `sandbox`, each answering one line to every connection, and
    /// waits until each answers inside the guest.
    fn drill_listen(self: &Arc<Self>, sandbox: &SandboxId, ports: &[u16]) -> Result<(), String> {
        let script = ports
            .iter()
            .map(|port| format!("nc -lk -p {port} -e /bin/echo drill-{port} & "))
            .collect::<String>()
            + "wait";
        let production = Arc::clone(self);
        let id = sandbox.clone();
        // The command lasts as long as the VM: the drill's stop ends it.
        let _ = thread::Builder::new()
            .name("drill-listener".to_owned())
            .spawn(move || {
                let _ = production.service.exec(
                    &id,
                    ExecRequest::new(script.into_bytes(), 4096, DRILL_LIFETIME),
                );
            });
        for port in ports {
            let deadline = Instant::now() + Duration::from_secs(30);
            loop {
                let probe = ExecRequest::new(
                    format!("nc -w 2 127.0.0.1 {port} </dev/null").into_bytes(),
                    4096,
                    Duration::from_secs(10),
                );
                if let Ok(outcome) = self.service.exec(sandbox, probe) {
                    if String::from_utf8_lossy(outcome.output.as_bytes()).contains("drill-") {
                        break;
                    }
                }
                if Instant::now() >= deadline {
                    return Err(format!(
                        "the drill's listener on port {port} of {sandbox} did not come up."
                    ));
                }
                thread::sleep(Duration::from_millis(300));
            }
        }
        Ok(())
    }

    /// One connection a program in `caller` makes to its endpoint `name` on `port`, judged from the
    /// host's counters: the caller's refused and admitted connections and the ingress streams
    /// `callee`'s link opened, during the attempt.
    fn drill_attempt(
        &self,
        caller: &SandboxId,
        name: &str,
        port: u16,
        callee: &SandboxId,
    ) -> DrillAttempt {
        let counters = || {
            let view = self.service.connections(caller);
            let opens = self
                .service
                .status()
                .into_iter()
                .find(|status| status.sandbox == *callee)
                .map_or(0, |status| status.ingress.opened);
            (view.refused_connections, view.admitted_connections, opens)
        };
        let before = counters();
        // What the program reads is not used: only the host's counters judge the attempt.
        let request = ExecRequest::new(
            format!("nc -w 4 {name} {port} </dev/null >/dev/null 2>&1; true").into_bytes(),
            4096,
            Duration::from_secs(20),
        );
        let _ = self.service.exec(caller, request);
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            let now = counters();
            let attempt = DrillAttempt {
                refused: now.0.saturating_sub(before.0),
                admitted: now.1.saturating_sub(before.1),
                callee_opens: now.2.saturating_sub(before.2),
            };
            let settled = attempt.refused > 0 || (attempt.admitted > 0 && attempt.callee_opens > 0);
            if settled || Instant::now() >= deadline {
                return attempt;
            }
            thread::sleep(Duration::from_millis(100));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::shared;

    #[test]
    fn shared_state_is_one_directory_or_one_inside_another() {
        let of = |paths: &[&str]| {
            shared(
                &paths
                    .iter()
                    .map(|path| Some((*path).to_owned()))
                    .collect::<Vec<_>>(),
            )
        };
        assert_eq!(
            of(&[r"D:\data\vm\a", r"D:\data\vm\b", r"D:\data\vm\c"]),
            Some(false)
        );
        assert_eq!(
            of(&[r"D:\data\vm\a", r"D:\Data\VM\A\"]),
            Some(true),
            "one directory, spelt twice"
        );
        assert_eq!(
            of(&["/var/lib/vm/a", "/var/lib/vm/a/inner"]),
            Some(true),
            "one inside another"
        );
        assert_eq!(
            of(&["/var/lib/vm/a", "/var/lib/vm/ab"]),
            Some(false),
            "a shared prefix is not nesting"
        );
        assert_eq!(shared(&[Some("x".to_owned()), None]), None);
    }
}
