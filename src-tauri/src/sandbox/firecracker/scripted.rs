//! Scripted ports for the backend tests: one simulated host whose launcher, API and
//! observation ports share their state, so that what the launcher does (running the
//! jailer, killing a cgroup) changes what the host observes. Nothing here touches the
//! real host.
//!
//! Running the jailer reads the jail's id, identity, cgroup and limits from the argument
//! vector the launcher was given and starts one simulated Firecracker process in the
//! jail's cgroup, with the jailed status of the status fixtures. The first process has
//! PID 48211, the fixtures' own, so a fixture status can stand in for it unchanged.

use std::cell::{RefCell, RefMut};
use std::collections::{BTreeMap, BTreeSet};
use std::rc::Rc;

use super::api::ApiCall;
use super::launcher::{ArtifactRole, Authorized, PrivilegedOperation};
use super::names::{HostPath, JailId};
use super::ports::{
    ApiFailure, ApiPort, ApiReply, CgroupState, HostObservationPort, HostState, InstanceInfo,
    LauncherFailure, LauncherPort, LauncherReport, ObservationFailure, ProcessObservation,
};
use super::status::fixtures::JAILED;
use crate::foundation::evidence::{ConfigurationFingerprint, OsKind};
use crate::foundation::ids::ContentKey;
use crate::foundation::process::{IdentityCheck, ProcessIdentity};
use crate::sandbox::backend::{Architecture, BuildId, HostBuild};

/// The cgroup v2 root of the fixture host.
const CGROUP_ROOT: &str = "/sys/fs/cgroup";
/// The PID of the first simulated process: the status fixtures' own.
pub(super) const FIRST_PID: u32 = 48211;

/// One thing a port was asked, in order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Event {
    Launcher {
        jail: JailId,
        step: Authorized,
        operation: PrivilegedOperation,
    },
    Api {
        socket: HostPath,
        path: String,
    },
    Describe {
        socket: HostPath,
    },
}

/// What the simulated host does; every field may be changed between calls.
pub(super) struct Script {
    pub(super) build: HostBuild,
    pub(super) configuration: ConfigurationFingerprint,
    /// The launcher fails every operation with this tag.
    pub(super) fail_op: Option<&'static str>,
    /// The launcher stages a root image with this content key instead.
    pub(super) staged_root_image: Option<ContentKey>,
    pub(super) jailer_code: i32,
    /// The jailer leaves a second process in the jail's cgroup.
    pub(super) second_process: bool,
    /// Firecracker refuses the call to this path.
    pub(super) refuse_path: Option<String>,
    /// The API port changes each call before writing it.
    pub(super) rewrite: Option<fn(&mut ApiCall)>,
    pub(super) vmm_version: String,
    pub(super) instance_state: String,
    /// A kill through the cgroup leaves the processes running.
    pub(super) survive_kill: bool,
    /// Whether the process holds a KVM VM descriptor.
    pub(super) kvm: bool,
    /// Changes each process observation before it is returned.
    pub(super) tamper: Option<fn(&mut ProcessObservation)>,
    /// Every host observation fails with this detail.
    pub(super) observation_failure: Option<String>,
}

#[derive(Clone, Debug)]
struct Process {
    identity: ProcessIdentity,
    cgroup: String,
    uid: u32,
    root: String,
    netns: String,
    limits: BTreeMap<String, String>,
    alive: bool,
    /// After it ended, another process took its PID.
    reused: bool,
}

struct State {
    script: Script,
    events: Vec<Event>,
    processes: Vec<Process>,
    cgroups: BTreeSet<String>,
    namespaces: BTreeMap<String, BTreeSet<String>>,
    next_pid: u32,
}

/// The simulated host, for the test to script and inspect.
#[derive(Clone)]
pub(super) struct Machine {
    state: Rc<RefCell<State>>,
}

pub(super) struct ScriptedLauncher(Rc<RefCell<State>>);
pub(super) struct ScriptedApi(Rc<RefCell<State>>);
pub(super) struct ScriptedHost(Rc<RefCell<State>>);

impl Machine {
    /// A Linux host under `configuration` where everything succeeds.
    pub(super) fn new(configuration: ConfigurationFingerprint, vmm_version: &str) -> Self {
        Self {
            state: Rc::new(RefCell::new(State {
                script: Script {
                    build: HostBuild {
                        os: OsKind::Linux,
                        build: BuildId::new("6.6.0").unwrap(),
                        architecture: Architecture::X86_64,
                    },
                    configuration,
                    fail_op: None,
                    staged_root_image: None,
                    jailer_code: 0,
                    second_process: false,
                    refuse_path: None,
                    rewrite: None,
                    vmm_version: vmm_version.to_owned(),
                    instance_state: "Running".to_owned(),
                    survive_kill: false,
                    kvm: true,
                    tamper: None,
                    observation_failure: None,
                },
                events: Vec::new(),
                processes: Vec::new(),
                cgroups: BTreeSet::new(),
                namespaces: BTreeMap::new(),
                next_pid: FIRST_PID,
            })),
        }
    }

    pub(super) fn ports(&self) -> (ScriptedLauncher, ScriptedApi, ScriptedHost) {
        (
            ScriptedLauncher(Rc::clone(&self.state)),
            ScriptedApi(Rc::clone(&self.state)),
            ScriptedHost(Rc::clone(&self.state)),
        )
    }

    pub(super) fn script(&self) -> RefMut<'_, Script> {
        RefMut::map(self.state.borrow_mut(), |state| &mut state.script)
    }

    pub(super) fn events(&self) -> Vec<Event> {
        self.state.borrow().events.clone()
    }

    /// The operations the launcher was asked to perform, in order.
    pub(super) fn operations(&self) -> Vec<PrivilegedOperation> {
        self.events()
            .into_iter()
            .filter_map(|event| match event {
                Event::Launcher { operation, .. } => Some(operation),
                _ => None,
            })
            .collect()
    }

    /// The tags of the operations the launcher was asked to perform, in order.
    pub(super) fn operation_tags(&self) -> Vec<&'static str> {
        self.operations()
            .iter()
            .map(PrivilegedOperation::tag)
            .collect()
    }

    /// The API paths called, in order.
    pub(super) fn api_paths(&self) -> Vec<String> {
        self.events()
            .into_iter()
            .filter_map(|event| match event {
                Event::Api { path, .. } => Some(path),
                _ => None,
            })
            .collect()
    }

    pub(super) fn forget_events(&self) {
        self.state.borrow_mut().events.clear();
    }

    /// Ends `process` on its own; with `reused`, another process then takes its PID.
    pub(super) fn end_process(&self, process: ProcessIdentity, reused: bool) {
        for found in self
            .state
            .borrow_mut()
            .processes
            .iter_mut()
            .filter(|found| found.identity == process)
        {
            found.alive = false;
            found.reused = reused;
        }
    }

    /// The processes that run now.
    pub(super) fn alive(&self) -> Vec<ProcessIdentity> {
        self.state
            .borrow()
            .processes
            .iter()
            .filter(|process| process.alive)
            .map(|process| process.identity)
            .collect()
    }

    /// The cgroups that exist now.
    pub(super) fn cgroups(&self) -> BTreeSet<String> {
        self.state.borrow().cgroups.clone()
    }

    /// The network namespaces that exist now.
    pub(super) fn namespaces(&self) -> BTreeSet<String> {
        self.state.borrow().namespaces.keys().cloned().collect()
    }
}

/// The value after `flag` in `argv`.
fn argument<'a>(argv: &'a [String], flag: &str) -> &'a str {
    argv.iter()
        .position(|item| item == flag)
        .and_then(|index| argv.get(index + 1))
        .map(String::as_str)
        .unwrap()
}

impl State {
    /// Runs the jailer of `argv`: starts the jail's Firecracker process in its cgroup.
    fn run_jailer(&mut self, argv: &[String]) {
        let id = argument(argv, "--id");
        let uid: u32 = argument(argv, "--uid").parse().unwrap();
        let exec_file = argument(argv, "--exec-file").rsplit('/').next().unwrap();
        let cgroup = format!("{CGROUP_ROOT}/{}/{id}", argument(argv, "--parent-cgroup"));
        let limits: BTreeMap<String, String> = argv
            .windows(2)
            .filter(|pair| pair[0] == "--cgroup")
            .map(|pair| {
                let (file, value) = pair[1].split_once('=').unwrap();
                (file.to_owned(), value.to_owned())
            })
            .chain([("cpu.weight".to_owned(), "100".to_owned())])
            .collect();
        self.cgroups.insert(cgroup.clone());
        if self.script.jailer_code != 0 {
            return;
        }
        let count = if self.script.second_process { 2 } else { 1 };
        for _ in 0..count {
            let pid = self.next_pid;
            self.next_pid += 1;
            self.processes.push(Process {
                identity: ProcessIdentity {
                    pid,
                    start_time_ticks: 900_000 + u64::from(pid),
                },
                cgroup: cgroup.clone(),
                uid,
                root: format!(
                    "{}/{exec_file}/{id}/root",
                    argument(argv, "--chroot-base-dir")
                ),
                netns: argument(argv, "--netns").to_owned(),
                limits: limits.clone(),
                alive: true,
                reused: false,
            });
        }
    }

    fn process(&self, identity: &ProcessIdentity) -> Option<&Process> {
        self.processes
            .iter()
            .find(|process| process.identity == *identity)
    }

    fn observation_failed(&self) -> Result<(), ObservationFailure> {
        match &self.script.observation_failure {
            Some(detail) => Err(ObservationFailure {
                detail: detail.clone(),
            }),
            None => Ok(()),
        }
    }
}

impl LauncherPort for ScriptedLauncher {
    fn perform(
        &mut self,
        jail: &JailId,
        step: Authorized,
        operation: &PrivilegedOperation,
    ) -> Result<LauncherReport, LauncherFailure> {
        let mut state = self.0.borrow_mut();
        state.events.push(Event::Launcher {
            jail: jail.clone(),
            step,
            operation: operation.clone(),
        });
        if state.script.fail_op == Some(operation.tag()) {
            return Err(LauncherFailure {
                detail: format!("scripted failure of {}", operation.tag()),
            });
        }
        Ok(match operation {
            PrivilegedOperation::CreateNetworkNamespace { netns } => {
                state.namespaces.insert(netns.to_string(), BTreeSet::new());
                LauncherReport::Done
            }
            PrivilegedOperation::CreateTapDevice { netns, device, .. } => {
                state
                    .namespaces
                    .entry(netns.to_string())
                    .or_default()
                    .insert(device.to_string());
                LauncherReport::Done
            }
            PrivilegedOperation::StageArtifact {
                role,
                content_key,
                length_bytes,
                ..
            } => LauncherReport::Staged {
                content_key: match (role, state.script.staged_root_image) {
                    (ArtifactRole::RootImage, Some(other)) => other,
                    _ => *content_key,
                },
                length_bytes: *length_bytes,
            },
            PrivilegedOperation::RunJailer { argv, .. } => {
                state.run_jailer(argv);
                LauncherReport::JailerExited {
                    code: state.script.jailer_code,
                }
            }
            PrivilegedOperation::TerminateJail { cgroup } => {
                if !state.script.survive_kill {
                    let cgroup = cgroup.to_string();
                    for process in state
                        .processes
                        .iter_mut()
                        .filter(|process| process.cgroup == cgroup)
                    {
                        process.alive = false;
                    }
                }
                LauncherReport::Done
            }
            PrivilegedOperation::RemoveCgroup { cgroup } => {
                state.cgroups.remove(cgroup.as_str());
                LauncherReport::Done
            }
            PrivilegedOperation::RemoveNetworkNamespace { netns } => {
                state.namespaces.remove(netns.as_str());
                LauncherReport::Done
            }
            PrivilegedOperation::CreateDirectory { .. }
            | PrivilegedOperation::CreateSink { .. }
            | PrivilegedOperation::RemoveJail { .. } => LauncherReport::Done,
        })
    }
}

impl ApiPort for ScriptedApi {
    fn send(&mut self, socket: &HostPath, call: &ApiCall) -> Result<ApiReply, ApiFailure> {
        let mut state = self.0.borrow_mut();
        state.events.push(Event::Api {
            socket: socket.clone(),
            path: call.path.clone(),
        });
        let mut sent = call.clone();
        if let Some(rewrite) = state.script.rewrite {
            rewrite(&mut sent);
        }
        if state.script.refuse_path.as_deref() == Some(call.path.as_str()) {
            return Ok(ApiReply {
                sent,
                status: 400,
                fault_message: Some("scripted refusal".to_owned()),
            });
        }
        Ok(ApiReply {
            sent,
            status: 204,
            fault_message: None,
        })
    }

    fn describe(&mut self, socket: &HostPath) -> Result<InstanceInfo, ApiFailure> {
        let mut state = self.0.borrow_mut();
        state.events.push(Event::Describe {
            socket: socket.clone(),
        });
        let components: Vec<&str> = socket.as_str().split('/').collect();
        let root = components.iter().position(|part| *part == "root").unwrap();
        Ok(InstanceInfo {
            id: components[root - 1].to_owned(),
            state: state.script.instance_state.clone(),
            vmm_version: state.script.vmm_version.clone(),
        })
    }
}

impl HostObservationPort for ScriptedHost {
    fn host(&self) -> Result<HostState, ObservationFailure> {
        let state = self.0.borrow();
        state.observation_failed()?;
        Ok(HostState {
            build: state.script.build.clone(),
            configuration: state.script.configuration,
        })
    }

    fn cgroup_processes(
        &self,
        cgroup: &HostPath,
    ) -> Result<Vec<ProcessIdentity>, ObservationFailure> {
        let state = self.0.borrow();
        state.observation_failed()?;
        Ok(state
            .processes
            .iter()
            .filter(|process| process.alive && process.cgroup == cgroup.as_str())
            .map(|process| process.identity)
            .collect())
    }

    fn cgroup_state(&self, cgroup: &HostPath) -> Result<CgroupState, ObservationFailure> {
        let state = self.0.borrow();
        state.observation_failed()?;
        let populated = state
            .processes
            .iter()
            .any(|process| process.alive && process.cgroup == cgroup.as_str());
        Ok(if populated {
            CgroupState::Populated
        } else if state.cgroups.contains(cgroup.as_str()) {
            CgroupState::Empty
        } else {
            CgroupState::Absent
        })
    }

    fn observe(
        &self,
        process: &ProcessIdentity,
        cgroup: &HostPath,
    ) -> Result<ProcessObservation, ObservationFailure> {
        let state = self.0.borrow();
        state.observation_failed()?;
        let Some(found) = state.process(process).filter(|found| found.alive) else {
            return Err(ObservationFailure {
                detail: format!("{process} no longer runs"),
            });
        };
        let mut descriptors: Vec<String> = [
            "/dev/null",
            "/dev/null",
            "/dev/null",
            "/dev/kvm",
            "socket:[4001]",
            "/sinks/log.fifo",
            "/sinks/metrics.fifo",
            "/images/rootfs.img",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect();
        if state.script.kvm {
            descriptors.extend(
                [
                    "anon_inode:kvm-vm",
                    "anon_inode:kvm-vcpu:0",
                    "anon_inode:kvm-vcpu:1",
                ]
                .into_iter()
                .map(str::to_owned),
            );
        }
        let mut interfaces: BTreeSet<String> = ["lo".to_owned()].into_iter().collect();
        if let Some(taps) = state.namespaces.get(&found.netns) {
            interfaces.extend(taps.iter().cloned());
        }
        let relative = found
            .cgroup
            .strip_prefix(CGROUP_ROOT)
            .unwrap_or(&found.cgroup);
        let limits = if found.cgroup == cgroup.as_str() {
            found.limits.clone()
        } else {
            BTreeMap::new()
        };
        let mut observation = ProcessObservation {
            status: JAILED
                .replace("48211", &found.identity.pid.to_string())
                .replace("64001", &found.uid.to_string()),
            cgroup: format!("0::{relative}\n"),
            root: found.root.clone(),
            descriptors,
            network_interfaces: interfaces,
            cgroup_files: limits,
        };
        if let Some(tamper) = state.script.tamper {
            tamper(&mut observation);
        }
        Ok(observation)
    }

    fn check(&self, process: &ProcessIdentity) -> Result<IdentityCheck, ObservationFailure> {
        let state = self.0.borrow();
        state.observation_failed()?;
        Ok(match state.process(process) {
            Some(found) if found.alive => IdentityCheck::Same,
            Some(found) if found.reused => IdentityCheck::Reused,
            _ => IdentityCheck::Gone,
        })
    }
}
