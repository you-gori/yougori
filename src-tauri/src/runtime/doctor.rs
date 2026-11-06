//! The engine's VM sandbox doctor and its automation method `sandbox_doctor`
//! (docs/combined-gpu-memory-and-vm-sandbox-plan.md: VM-W23, line 2622, "Host-specific
//! capability/evidence doctor adapters in CORE-01, with freshness and effect on
//! requirements. Report changes without altering host settings silently"; its file map,
//! line 3078, names this file).
//!
//! `status` (the default) examines this computer with [`crate::sandbox::doctor`]: one
//! boundary report per backend the plan names for this operating system, for the run
//! profiles asked (strict when none), each labelled validated, experimental or unavailable
//! (§7.1, lines 2356–2364), every check that did not pass in the engine's words, and what
//! changed since the previous examination. `plan` describes every check for this host
//! without running anything.
//!
//! The previous reports are kept in one small file under the engine's data directory
//! ([`HISTORY_FILE`]), replaced atomically after every examination, so the comparison
//! survives a restart. `sandbox::doctor` reads the file strictly, once per engine run: a
//! damaged or unreadable file is reported in the report and ignored, never trusted.
//!
//! Check results come from one source so far: the launch records the VM sandboxes of this
//! engine run sealed (the Windows QEMU/WHPX backend, `sandbox_vm`), each giving exactly the
//! check parts its host-observed facts decide (`sandbox::probes::RecordResults`), judged
//! fresh for [`RESULT_MAX_AGE`]. Every other check needs a host check runner that is not
//! connected yet and reads not tested, so no backend is validated. The doctor never starts a
//! VM, never composes the sandbox service and never changes the host. The host build and
//! configuration come from `host_evidence`'s latest inventory, on its registry's clock;
//! until it has collected one, `status` says so instead of guessing.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{self, Read};
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock, PoisonError};
use std::time::Duration;

use serde_json::{json, Value};

use crate::foundation::events::write_atomic;
use crate::foundation::evidence::{ConfigurationFingerprint, OsKind};
use crate::host_evidence::{host_fingerprint, HostInventory};
use crate::sandbox::backend::{Architecture, BuildId, HostBuild};
use crate::sandbox::doctor::{
    plan, run_profile, Doctor, DoctorRequest, HistoryStore, StoreFailure, DEFAULT_PROFILES,
    HISTORY_LIMIT,
};
use crate::sandbox::probes::{CheckId, CheckInput, JudgeContext, RecordResults, RunProfile};
use crate::AppHandle;

/// How old a check result may be when the doctor judges it.
const RESULT_MAX_AGE: Duration = Duration::from_secs(15 * 60);

/// What the doctor says about where its results come from.
const CHECK_RUNNER: &str = "Check results are read only from the launch records this engine run's VM sandboxes sealed (host-observed facts, fresh for 15 minutes); the other checks need host check runners that are not connected yet and read not tested, so no backend is validated.";
/// Why no confinement verdict was given.
const NO_CONFINEMENT: &str = "No sandbox's confinement was probed in this engine run; run `yougori sandbox confinement SANDBOX_ID` on a running sandbox and ask again within 15 minutes.";
/// The §17 row of the inner confinement check.
const VM_CP_05: u8 = 5;
/// Why no launch record was read.
const NO_RECORDS: &str = "No VM sandbox ran in this engine run, so no launch record was read; launch one (`yougori sandbox launch`) and ask again within 15 minutes.";

/// The file under the engine's data directory that keeps the doctor's previous reports.
const HISTORY_FILE: &str = "sandbox-doctor-history.json";

static DOCTOR: OnceLock<Mutex<Doctor<HistoryFile>>> = OnceLock::new();

/// The doctor's store: one file, read at most [`HISTORY_LIMIT`] + 1 bytes at a time and
/// replaced atomically (a synced temporary sibling renamed over it).
struct HistoryFile {
    /// The file, or why the engine's data directory is not known.
    path: Result<PathBuf, String>,
}

fn store_failure(error: io::Error) -> StoreFailure {
    StoreFailure {
        detail: error.to_string(),
    }
}

impl HistoryFile {
    fn path(&self) -> Result<&PathBuf, StoreFailure> {
        self.path.as_ref().map_err(|detail| StoreFailure {
            detail: format!("the engine's data directory is not known: {detail}"),
        })
    }
}

impl HistoryStore for HistoryFile {
    fn read(&mut self) -> Result<Option<Vec<u8>>, StoreFailure> {
        let file = match File::open(self.path()?) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(store_failure(error)),
        };
        let mut bytes = Vec::new();
        file.take(HISTORY_LIMIT as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(store_failure)?;
        Ok(Some(bytes))
    }

    fn replace(&mut self, bytes: &[u8]) -> Result<(), StoreFailure> {
        write_atomic(self.path()?, bytes).map_err(store_failure)
    }
}

/// The engine's one doctor, keeping its history under the data directory of `app`.
fn engine_doctor(app: &AppHandle) -> &'static Mutex<Doctor<HistoryFile>> {
    DOCTOR.get_or_init(|| {
        Mutex::new(Doctor::with_store(HistoryFile {
            path: crate::acceptance::app_data(app).map(|folder| folder.join(HISTORY_FILE)),
        }))
    })
}

fn encoded(value: impl serde::Serialize) -> Result<Value, String> {
    serde_json::to_value(value).map_err(|error| error.to_string())
}

/// The run profiles named in `names`, or the strict profile when none is named.
fn profiles(names: Option<Vec<String>>) -> Result<BTreeSet<RunProfile>, String> {
    let Some(names) = names.filter(|names| !names.is_empty()) else {
        return Ok(DEFAULT_PROFILES.into_iter().collect());
    };
    names
        .iter()
        .map(|name| {
            run_profile(name).ok_or_else(|| {
                format!(
                    "Unknown run profile '{name}'. Use strict, transport, pool, gpu_vm, remote, confidential, drill, release or research."
                )
            })
        })
        .collect()
}

fn architecture(name: &str) -> Option<Architecture> {
    match name {
        "x86_64" => Some(Architecture::X86_64),
        "aarch64" => Some(Architecture::Aarch64),
        _ => None,
    }
}

/// This host's build and configuration from `inventory`, or why they are not known.
fn host_of(
    inventory: Option<&HostInventory>,
) -> Result<(HostBuild, ConfigurationFingerprint), &'static str> {
    let inventory =
        inventory.ok_or("Host evidence has not collected this computer's inventory yet.")?;
    let os = inventory
        .os
        .as_ref()
        .ok_or("Host evidence could not tell this computer's operating system.")?;
    let build = os
        .build
        .as_deref()
        .ok_or("Host evidence could not read this computer's operating system build.")?;
    let host = HostBuild {
        os: os.kind,
        build: BuildId::new(build)
            .map_err(|_| "Host evidence read an operating system build the doctor cannot name.")?,
        architecture: architecture(&os.architecture)
            .ok_or("This computer's architecture has no VM sandbox backend.")?,
    };
    let configuration = host_fingerprint(inventory)
        .map_err(|_| "Host evidence could not fingerprint this computer's configuration.")?;
    Ok((host, configuration))
}

/// The operating system this engine was built for, for a plan before any inventory.
fn built_for() -> Option<OsKind> {
    if cfg!(target_os = "windows") {
        Some(OsKind::Windows)
    } else if cfg!(target_os = "linux") {
        Some(OsKind::Linux)
    } else if cfg!(target_os = "macos") {
        Some(OsKind::MacOs)
    } else {
        None
    }
}

/// The `sandbox_doctor` desktop command, for the doctor view
/// (`src/components/security/doctor.tsx`): the same answer as the automation method.
#[tauri::command]
pub async fn sandbox_doctor(
    app: AppHandle,
    action: Option<String>,
    profiles: Option<Vec<String>>,
) -> Result<Value, String> {
    dispatch(app, action, profiles).await
}

/// The `sandbox_doctor` automation method: `status` (the default) or `plan`.
pub(crate) async fn dispatch(
    app: AppHandle,
    action: Option<String>,
    profile_names: Option<Vec<String>>,
) -> Result<Value, String> {
    let profiles = profiles(profile_names)?;
    match action.as_deref().unwrap_or("status") {
        "plan" => {
            let (inventory, _) = crate::host_evidence::inventory_and_now().await?;
            let os = inventory
                .as_ref()
                .and_then(|inventory| inventory.os.as_ref())
                .map(|os| os.kind)
                .or_else(built_for)
                .ok_or("This operating system has no VM sandbox backend.")?;
            encoded(plan(os, &profiles))
        }
        "status" => {
            let (inventory, now) = crate::host_evidence::inventory_and_now().await?;
            let (host, configuration) = match host_of(inventory.as_ref()) {
                Ok(known) => known,
                Err(reason) => {
                    return Ok(json!({
                        "examined": false,
                        "reason": reason,
                        "next": "Run `yougori call host_evidence --action refresh` first; it runs bounded, read-only queries and changes nothing.",
                    }))
                }
            };
            let request = DoctorRequest {
                host: host.clone(),
                configuration,
                profiles,
            };
            // The sandboxes of this engine run, when any ran: their launch records, the latest
            // confinement verdict, and the service's evidence clock they were stamped on.
            let launched = crate::sandbox_vm::doctor_records().await;
            // Their evidence is judged on the clock it was stamped on; the host evidence
            // inventory keeps another, so a record read on it would be refused as observed
            // on another clock (found 30 October 2026).
            let judge_now = launched
                .as_ref()
                .and_then(|launched| launched.now)
                .unwrap_or(now);
            let context = JudgeContext {
                now: judge_now,
                configuration,
                max_age: RESULT_MAX_AGE,
                os: host.os,
            };
            // The sealed launch records of this engine run's VM sandboxes, when any ran: each
            // gives the check parts its host-observed facts decide. A record of another host
            // or backend build is refused and named.
            let (records, launch_records, confinement) = match launched {
                Some(crate::sandbox_vm::DoctorRecords { backend, records: launched, negatives, scans, drills, confinement, .. }) => {
                    let mut results = RecordResults::new(host.clone(), backend.clone());
                    let given = launched.len();
                    let refused: Vec<String> = launched
                        .into_iter()
                        .filter_map(|record| results.record(record).err().map(|error| error.to_string()))
                        .collect();
                    // Controlled negative launches (an acceptance build plants the fault):
                    // each decides its positive control when the backend refused it for
                    // the fault's own reason.
                    let negative_given = negatives.len();
                    let negative_refused: Vec<String> = negatives
                        .into_iter()
                        .filter_map(|(fault, outcome)| results.negative(fault, outcome).err().map(|error| error.to_string()))
                        .collect();
                    // The host's scans of its process list: one taken now, and one after each
                    // refused negative launch, with what each found.
                    let scan_views: Vec<Value> = scans
                        .iter()
                        .map(|scan| {
                            let found = scan.value();
                            json!({
                                "moment": found.moment,
                                "processes": found.processes,
                                "hypervisors": found.hypervisors,
                                "started_during_attempt": found.started_during_attempt,
                                "emulated_hypervisor": found.emulated_hypervisor(),
                                "fallback_started": found.fallback_started(),
                            })
                        })
                        .collect();
                    for scan in scans {
                        results.scan(scan);
                    }
                    // The VM-CP-29 connection drills `yougori sandbox drill vm-cp-29` ran, each
                    // with the host's counters of its attempts.
                    let drill_views: Vec<Value> = drills
                        .iter()
                        .map(|drill| json!({ "attempts": drill.value().attempts.iter().map(|(case, attempt)| json!({ "case": case, "refused": attempt.refused(), "host_observed": attempt })).collect::<Vec<_>>(), "shared_state": drill.value().shared_state }))
                        .collect();
                    for drill in drills {
                        results.drill(drill);
                    }
                    let view = json!({
                        "backend": encoded(&backend)?,
                        "given": given,
                        "read": results.normal_launches(),
                        "refused": refused,
                        "negative": {
                            "given": negative_given,
                            "read": results.negative_launches(),
                            "refused": negative_refused,
                        },
                        "process_scans": scan_views,
                        "connection_drills": drill_views,
                    });
                    (Some(results), view, confinement.map(|evaluation| (backend.kind, evaluation)))
                }
                None => (None, json!({ "given": 0, "reason": NO_RECORDS }), None),
            };
            // The latest strict-profile confinement verdict, VM-CP-05's input for its
            // backend; the judge refuses it once stale or under another configuration.
            let mut inputs = BTreeMap::new();
            let confinement_view = match (confinement, CheckId::new(VM_CP_05)) {
                (Some((backend, evaluation)), Some(check)) => {
                    let view = json!({
                        "evaluated": true,
                        "outcome": encoded(&evaluation.verdict().outcome)?,
                    });
                    inputs.insert(backend, BTreeMap::from([(check, CheckInput::Vm05(evaluation))]));
                    view
                }
                _ => json!({ "evaluated": false, "reason": NO_CONFINEMENT }),
            };
            // The examination reads and replaces the history file, so it runs off the
            // async workers.
            let doctor = engine_doctor(&app);
            let report = tokio::task::spawn_blocking(move || {
                let mut doctor = doctor.lock().unwrap_or_else(PoisonError::into_inner);
                match records {
                    Some(results) => doctor.examine_with_records(
                        &request,
                        &context,
                        inputs,
                        std::slice::from_ref(&results),
                    ),
                    None => doctor.examine(&request, &context, inputs),
                }
            })
            .await
            .map_err(|error| error.to_string())?
            .map_err(|error| error.to_string())?;
            Ok(json!({
                "examined": true,
                "checkRunner": CHECK_RUNNER,
                "launchRecords": launch_records,
                "confinement": confinement_view,
                "report": encoded(report)?,
            }))
        }
        other => Err(format!(
            "Unknown sandbox doctor action '{other}'. Use status or plan."
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profiles_default_to_strict_and_refuse_unknown_names() {
        assert_eq!(
            profiles(None).unwrap(),
            BTreeSet::from([RunProfile::Strict])
        );
        assert_eq!(
            profiles(Some(Vec::new())).unwrap(),
            BTreeSet::from([RunProfile::Strict])
        );
        assert_eq!(
            profiles(Some(vec!["strict".into(), "gpu_vm".into()])).unwrap(),
            BTreeSet::from([RunProfile::Strict, RunProfile::GpuVm])
        );
        assert!(profiles(Some(vec!["lenient".into()]))
            .unwrap_err()
            .contains("Unknown run profile 'lenient'"));
    }

    #[test]
    fn the_history_file_reads_what_it_replaced_and_no_more_than_a_history_may_hold() {
        let folder = tempfile::tempdir().unwrap();
        let mut file = HistoryFile {
            path: Ok(folder.path().join(HISTORY_FILE)),
        };
        assert_eq!(file.read().unwrap(), None);
        file.replace(b"first").unwrap();
        file.replace(b"second").unwrap();
        assert_eq!(file.read().unwrap().as_deref(), Some(&b"second"[..]));
        let names: Vec<_> = std::fs::read_dir(folder.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(names, vec![std::ffi::OsString::from(HISTORY_FILE)]);
        file.replace(&vec![b' '; HISTORY_LIMIT + 10]).unwrap();
        assert_eq!(file.read().unwrap().unwrap().len(), HISTORY_LIMIT + 1);

        let mut unknown = HistoryFile {
            path: Err("no app data folder".to_owned()),
        };
        assert!(unknown
            .read()
            .unwrap_err()
            .detail
            .contains("no app data folder"));
        assert!(unknown.replace(b"kept").is_err());
    }

    #[test]
    fn without_an_inventory_the_doctor_says_why_instead_of_guessing() {
        assert!(host_of(None).unwrap_err().contains("not collected"));
        assert_eq!(architecture("x86_64"), Some(Architecture::X86_64));
        assert_eq!(architecture("aarch64"), Some(Architecture::Aarch64));
        assert_eq!(architecture("riscv64"), None);
    }
}
