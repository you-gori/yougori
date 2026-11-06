//! Host scans of the process list, the host-observed facts behind VM-CP-01's
//! `cp01.no-tcg-hypervisor` ("the host process list shows no hypervisor running with a TCG
//! argument") and VM-CP-33's `cp33.fallback-start` ("the process list shows no native,
//! emulated or container start"), §17 lines 3151 and 3183.
//!
//! A host runner (the engine's, `sandbox_vm::process_scan` on Windows) reads the process
//! list and gives each process as a [`ListedProcess`]: its id, its parent's, its image name,
//! its creation time and, for a hypervisor process, its command line when it could be read.
//! [`ProcessScan::build`] turns that list into the facts the checks read, and
//! [`RecordResults`](super::RecordResults) takes the scan stamped as a host observation:
//!
//! - an **examination** scan, taken when the doctor examines, decides whether any hypervisor
//!   on the host runs emulated. A QEMU names its accelerator with `-accel`, `-machine
//!   accel=` or `-enable-kvm`; one that names none, or names TCG anywhere (a fallback chain
//!   such as `-accel whpx -accel tcg` included), runs emulated. A hypervisor process whose
//!   command line could not be read leaves the observation undecided: the scan cannot show
//!   that it is not emulated;
//! - an **after-refusal** scan, taken right after the backend refused a controlled negative
//!   launch (the hypervisor or the GPU path made unavailable on purpose), against the list
//!   taken right before it: a process the engine started during the attempt (a descendant of
//!   the engine created after the earlier list) that still runs is a fallback start, native,
//!   emulated or container alike. The engine's other work, started before, is not the
//!   refused launch's.
//!
//! Command lines are read to classify hypervisors only; a scan keeps image names, process ids
//! and the classification, never a command line, which may hold a path or a secret.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use super::records::ControlledFault;

/// When a scan was taken.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "moment", rename_all = "snake_case")]
pub enum ScanMoment {
    /// When the doctor examined: what runs on the host now.
    Examination,
    /// Right after the backend refused a controlled negative launch with `fault`.
    AfterRefusal { fault: ControlledFault },
}

/// One process of the host's list, as the runner read it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ListedProcess {
    pub pid: u32,
    pub parent: u32,
    /// The executable's file name, such as `qemu-system-x86_64.exe`.
    pub image: String,
    /// When the process was created, in the host's own units (a later process has a
    /// larger value); `None` when it could not be read.
    pub created: Option<u64>,
    /// The command line of a hypervisor process when the runner could read it.
    pub command_line: Option<Vec<String>>,
}

/// How a hypervisor process runs, from its command line.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "runs", rename_all = "snake_case")]
pub enum HypervisorMode {
    /// It names hardware accelerators only.
    Hardware { accelerators: Vec<String> },
    /// It names TCG, or no accelerator at all (QEMU's default then is TCG).
    Emulated,
    /// Its command line could not be read.
    Unread,
}

/// A hypervisor process the scan saw.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SeenHypervisor {
    pub pid: u32,
    pub image: String,
    pub mode: HypervisorMode,
    /// Whether the engine started it (it descends from the engine's process).
    pub started_by_engine: bool,
}

/// A process the engine started during a refused launch that still runs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct LeftoverStart {
    pub pid: u32,
    pub image: String,
}

/// What one scan of the process list showed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ProcessScan {
    pub moment: ScanMoment,
    /// How many processes the list held.
    pub processes: usize,
    /// Every hypervisor process on the host, with how it runs.
    pub hypervisors: Vec<SeenHypervisor>,
    /// After a refusal: the processes the engine started during the attempt that still run.
    pub started_during_attempt: Vec<LeftoverStart>,
    /// After a refusal: whether the list taken before the attempt was given; without it no
    /// start can be attributed to the attempt.
    pub compared_with_before: bool,
}

/// Whether `image` is a hypervisor's executable: QEMU's system emulators.
pub fn is_hypervisor_image(image: &str) -> bool {
    let image = image.to_ascii_lowercase();
    image.starts_with("qemu-system-") || image == "qemu-kvm" || image == "qemu-kvm.exe"
}

/// How a QEMU with `command_line` (the executable, then its arguments) runs: emulated when
/// it names TCG anywhere or names no accelerator, otherwise on the hardware accelerators it
/// names.
pub fn hypervisor_mode(command_line: &[String]) -> HypervisorMode {
    let arguments = command_line.get(1..).unwrap_or_default();
    let mut accelerators = Vec::new();
    let mut tcg = false;
    let mut index = 0;
    while index < arguments.len() {
        let argument = arguments[index].trim_start_matches('-');
        let value = arguments.get(index + 1).map(String::as_str);
        // `-option value` and `-option=value` both occur.
        let (option, inline) = match argument.split_once('=') {
            Some((option, inline)) => (option, Some(inline)),
            None => (argument, None),
        };
        let named = |text: &str| -> Vec<String> {
            text.split([',', ':'])
                .map(|word| word.trim().to_ascii_lowercase())
                .filter(|word| !word.is_empty() && !word.contains('='))
                .collect()
        };
        match option {
            "accel" => {
                let text = inline.or(value).unwrap_or_default();
                // `-accel whpx,kernel-irqchip=off`: the first item names the accelerator.
                if let Some(first) = text.split(',').next() {
                    accelerators.extend(named(first));
                }
                if inline.is_none() {
                    index += 1;
                }
            }
            "machine" | "M" => {
                let text = inline.or(value).unwrap_or_default();
                for item in text.split(',') {
                    if let Some(listed) = item.strip_prefix("accel=") {
                        accelerators.extend(named(listed));
                    }
                }
                if inline.is_none() {
                    index += 1;
                }
            }
            "enable-kvm" => accelerators.push("kvm".to_owned()),
            _ => {}
        }
        index += 1;
    }
    for argument in arguments {
        if argument
            .split([',', '=', ':', ' '])
            .any(|word| word.eq_ignore_ascii_case("tcg"))
        {
            tcg = true;
        }
    }
    if tcg || accelerators.is_empty() || accelerators.iter().any(|name| name == "tcg") {
        return HypervisorMode::Emulated;
    }
    accelerators.sort();
    accelerators.dedup();
    HypervisorMode::Hardware { accelerators }
}

/// The processes that descend from `root` in `list`: children by parent id, each created no
/// earlier than its parent when both creation times are known (a reused parent id is not a
/// parent).
fn descendants(list: &[ListedProcess], root: u32) -> BTreeSet<u32> {
    let by_pid: BTreeMap<u32, &ListedProcess> = list.iter().map(|process| (process.pid, process)).collect();
    let mut found = BTreeSet::new();
    let mut frontier = vec![root];
    while let Some(parent) = frontier.pop() {
        let parent_created = by_pid.get(&parent).and_then(|process| process.created);
        for child in list.iter().filter(|process| process.parent == parent && process.pid != parent) {
            let after_parent = match (parent_created, child.created) {
                (Some(parent), Some(child)) => child >= parent,
                _ => true,
            };
            if after_parent && found.insert(child.pid) {
                frontier.push(child.pid);
            }
        }
    }
    found
}

impl ProcessScan {
    /// The scan of `list` taken at `moment` by the engine running as `engine`. `before` is the
    /// list taken right before a negative launch, for an after-refusal scan.
    pub fn build(
        moment: ScanMoment,
        list: &[ListedProcess],
        engine: u32,
        before: Option<&[ListedProcess]>,
    ) -> Self {
        let ours = descendants(list, engine);
        let hypervisors = list
            .iter()
            .filter(|process| is_hypervisor_image(&process.image))
            .map(|process| SeenHypervisor {
                pid: process.pid,
                image: process.image.clone(),
                mode: process
                    .command_line
                    .as_deref()
                    .map_or(HypervisorMode::Unread, hypervisor_mode),
                started_by_engine: ours.contains(&process.pid),
            })
            .collect();
        let started_during_attempt = match (moment, before) {
            (ScanMoment::AfterRefusal { .. }, Some(before)) => {
                // A process of the earlier list is the same process when its id and its
                // creation time match.
                let earlier: BTreeSet<(u32, Option<u64>)> = before
                    .iter()
                    .map(|process| (process.pid, process.created))
                    .collect();
                list.iter()
                    .filter(|process| ours.contains(&process.pid))
                    .filter(|process| !earlier.contains(&(process.pid, process.created)))
                    .map(|process| LeftoverStart {
                        pid: process.pid,
                        image: process.image.clone(),
                    })
                    .collect()
            }
            _ => Vec::new(),
        };
        Self {
            moment,
            processes: list.len(),
            hypervisors,
            started_during_attempt,
            compared_with_before: before.is_some(),
        }
    }

    /// Whether any hypervisor on the host runs emulated; `None` when a hypervisor's command
    /// line could not be read, since the scan cannot show that it does not.
    pub fn emulated_hypervisor(&self) -> Option<bool> {
        if self
            .hypervisors
            .iter()
            .any(|seen| seen.mode == HypervisorMode::Unread)
        {
            return None;
        }
        Some(
            self.hypervisors
                .iter()
                .any(|seen| seen.mode == HypervisorMode::Emulated),
        )
    }

    /// After a refusal: whether a start of the refused launch still runs; `None` for a scan
    /// of another moment or one taken without the list from before the attempt.
    pub fn fallback_started(&self) -> Option<bool> {
        match self.moment {
            ScanMoment::AfterRefusal { .. } if self.compared_with_before => {
                Some(!self.started_during_attempt.is_empty())
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line(text: &str) -> Vec<String> {
        text.split_whitespace().map(str::to_owned).collect()
    }

    fn process(pid: u32, parent: u32, image: &str, created: u64, command: Option<&str>) -> ListedProcess {
        ListedProcess {
            pid,
            parent,
            image: image.to_owned(),
            created: Some(created),
            command_line: command.map(line),
        }
    }

    /// PROVES a QEMU runs emulated when it names TCG anywhere or no accelerator at all, and on
    /// hardware only when every accelerator it names is one.
    #[test]
    fn the_accelerator_is_read_from_the_command_line() {
        let hardware = |text: &str| HypervisorMode::Hardware {
            accelerators: text.split(',').map(str::to_owned).collect(),
        };
        assert_eq!(hypervisor_mode(&line("qemu -accel whpx,kernel-irqchip=off -m 256")), hardware("whpx"));
        assert_eq!(hypervisor_mode(&line("qemu -machine microvm,accel=kvm -m 256")), hardware("kvm"));
        assert_eq!(hypervisor_mode(&line("qemu -enable-kvm")), hardware("kvm"));
        assert_eq!(hypervisor_mode(&line("qemu -accel tcg")), HypervisorMode::Emulated);
        assert_eq!(hypervisor_mode(&line("qemu -accel whpx -accel tcg")), HypervisorMode::Emulated);
        assert_eq!(hypervisor_mode(&line("qemu -machine pc,accel=whpx:tcg")), HypervisorMode::Emulated);
        assert_eq!(hypervisor_mode(&line("qemu -m 256 -nographic")), HypervisorMode::Emulated, "no accelerator is TCG");
        assert_eq!(hypervisor_mode(&line("qemu -accel=hvf")), hardware("hvf"));
    }

    /// PROVES the examination decides only when every hypervisor was read: any emulated one
    /// is present, an unread one leaves it undecided, none is absent.
    #[test]
    fn an_examination_finds_emulated_hypervisors_and_never_guesses() {
        let engine = 10;
        let list = vec![
            process(10, 1, "yougori-engine.exe", 100, None),
            process(20, 10, "qemu-system-x86_64.exe", 200, Some("qemu -accel whpx,kernel-irqchip=off")),
            process(30, 1, "explorer.exe", 50, None),
        ];
        let scan = ProcessScan::build(ScanMoment::Examination, &list, engine, None);
        assert_eq!(scan.emulated_hypervisor(), Some(false));
        assert!(scan.hypervisors[0].started_by_engine);
        assert_eq!(scan.fallback_started(), None);
        let mut emulated = list.clone();
        emulated.push(process(40, 1, "qemu-system-x86_64.exe", 300, Some("qemu -m 128")));
        assert_eq!(ProcessScan::build(ScanMoment::Examination, &emulated, engine, None).emulated_hypervisor(), Some(true));
        let mut unread = list.clone();
        unread.push(process(50, 1, "qemu-system-aarch64.exe", 300, None));
        assert_eq!(ProcessScan::build(ScanMoment::Examination, &unread, engine, None).emulated_hypervisor(), None);
    }

    /// PROVES an after-refusal scan names exactly the engine's processes created during the
    /// attempt that still run: the engine's earlier work, other users' processes and a reused
    /// process id are not starts of the refused launch.
    #[test]
    fn an_after_refusal_scan_names_only_the_attempts_leftovers() {
        let engine = 10;
        let fault = ScanMoment::AfterRefusal { fault: ControlledFault::HypervisorUnavailable };
        let before = vec![
            process(10, 1, "yougori-engine.exe", 100, None),
            process(20, 10, "qemu-system-x86_64.exe", 200, Some("qemu -accel whpx")),
            process(30, 1, "notepad.exe", 50, None),
        ];
        // The refused QEMU is gone; nothing else was started.
        let clean = ProcessScan::build(fault, &before, engine, Some(&before));
        assert_eq!(clean.fallback_started(), Some(false));
        // A process the engine started during the attempt still runs, and another user's
        // new process and a child of a process that only reuses the engine's id do not count.
        let mut after = before.clone();
        after.push(process(60, 10, "qemu-system-x86_64.exe", 400, Some("qemu -accel tcg")));
        after.push(process(70, 1, "cmd.exe", 410, None));
        let leftover = ProcessScan::build(fault, &after, engine, Some(&before));
        assert_eq!(leftover.fallback_started(), Some(true));
        assert_eq!(leftover.started_during_attempt, vec![LeftoverStart { pid: 60, image: "qemu-system-x86_64.exe".to_owned() }]);
        let reused = vec![
            process(10, 1, "yougori-engine.exe", 100, None),
            process(80, 10, "qemu-system-x86_64.exe", 90, Some("qemu -accel whpx")),
        ];
        assert_eq!(ProcessScan::build(fault, &reused, engine, Some(&before[..1])).fallback_started(), Some(false), "created before the engine: not its child");
        // Without the earlier list nothing can be attributed.
        assert_eq!(ProcessScan::build(fault, &after, engine, None).fallback_started(), None);
    }
}
