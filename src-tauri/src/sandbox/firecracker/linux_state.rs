//! VM-CP-04's Linux expected state as a comparator over a typed observed state (line
//! 2979: `/proc/<vmm pid>/status` shows the launcher's unprivileged uid, `NoNewPrivs: 1`,
//! `Seccomp: 2`; the hypervisor's network namespace lists only `lo`; cgroup limits
//! present; open descriptor count at or below the profile's number; VM-P04 line 2779:
//! verified independently of the guest).
//!
//! The expected state comes from the launch plan; the observed state is what the host
//! read about the Firecracker process, never what the guest reports. Two checks follow
//! from the jail plan beyond the VM-CP-04 list: the permitted, effective and ambient
//! capability sets are empty, and the process is PID 1 of a nested PID namespace. A
//! declared network interface adds its tap device to the expected interfaces; otherwise
//! only `lo` is expected. Every check is reported with what was expected and observed, so
//! the positive control, the same checks on an unjailed launch, shows each difference.
//!
//! [`LinuxStateReport::observed_controls`] names the §1.3 hypervisor-confinement controls
//! the passing checks show. Filesystem limits are not among them: VM-CP-04 observes no
//! chroot, so that control needs its own host observation.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::time::Duration;

use serde::Serialize;

use super::jailer::{CgroupFile, CgroupLimit};
use super::names::{CgroupPath, InterfaceName, JailIdentity};
use super::status::{ProcStatus, SeccompMode};
use crate::foundation::evidence::{ClockReading, ConfigurationFingerprint};
use crate::sandbox::backend::{ConfinementControl, HostObserved, ObservationProblem};

/// What the host must observe about the jailed Firecracker process.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ExpectedLinuxState {
    pub identity: JailIdentity,
    /// `lo` and one tap device per declared interface.
    pub network_interfaces: BTreeSet<InterfaceName>,
    /// The jail's cgroup, relative to the cgroup v2 root.
    pub cgroup: CgroupPath,
    pub cgroup_limits: Vec<CgroupLimit>,
    pub max_open_descriptors: u32,
}

/// What the host observed about the Firecracker process.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ObservedLinuxState {
    /// The parsed `/proc/<pid>/status`.
    pub status: ProcStatus,
    /// The interface names in the process's network namespace.
    pub network_interfaces: BTreeSet<String>,
    /// The process's cgroup v2 path as `/proc/<pid>/cgroup` shows it, with a leading '/'.
    pub cgroup: String,
    /// The cgroup's interface files, by name, each without its final newline.
    pub cgroup_files: BTreeMap<String, String>,
    /// The number of entries in `/proc/<pid>/fd`.
    pub open_descriptors: u64,
}

/// One item of the comparison.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(tag = "item", rename_all = "snake_case")]
pub enum StateItem {
    Uid,
    Gid,
    Capabilities,
    NoNewPrivs,
    Seccomp,
    PidNamespace,
    NetworkInterfaces,
    Cgroup,
    CgroupLimit { file: CgroupFile },
    OpenDescriptors,
}

impl fmt::Display for StateItem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Uid => f.write_str("user ids"),
            Self::Gid => f.write_str("group ids"),
            Self::Capabilities => f.write_str("capability sets"),
            Self::NoNewPrivs => f.write_str("NoNewPrivs"),
            Self::Seccomp => f.write_str("seccomp mode"),
            Self::PidNamespace => f.write_str("PID namespace"),
            Self::NetworkInterfaces => f.write_str("network namespace interfaces"),
            Self::Cgroup => f.write_str("cgroup"),
            Self::CgroupLimit { file } => write!(f, "cgroup limit {file}"),
            Self::OpenDescriptors => f.write_str("open descriptors"),
        }
    }
}

/// One comparison, with both sides as text.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct StateCheck {
    pub item: StateItem,
    pub expected: String,
    pub observed: String,
    pub passed: bool,
}

impl fmt::Display for StateCheck {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}: expected {}, observed {} ({})",
            self.item,
            self.expected,
            self.observed,
            if self.passed { "pass" } else { "fail" }
        )
    }
}

/// Every VM-CP-04 check for one process.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct LinuxStateReport {
    checks: Vec<StateCheck>,
}

impl LinuxStateReport {
    pub fn checks(&self) -> &[StateCheck] {
        &self.checks
    }

    /// Whether every check passed.
    pub fn passed(&self) -> bool {
        self.checks.iter().all(|check| check.passed)
    }

    /// The checks that failed.
    pub fn failed(&self) -> Vec<&StateCheck> {
        self.checks.iter().filter(|check| !check.passed).collect()
    }

    fn all_passed(&self, wanted: impl Fn(StateItem) -> bool) -> bool {
        let mut relevant = self
            .checks
            .iter()
            .filter(|check| wanted(check.item))
            .peekable();
        relevant.peek().is_some() && relevant.all(|check| check.passed)
    }

    /// The hypervisor-confinement controls the passing checks show: account identity
    /// from the ids; process identity from empty capabilities with no_new_privs (the
    /// Linux counterpart of a restricted token); syscall restrictions from seccomp
    /// filters with no_new_privs; OS restrictions from the namespaces; resource controls
    /// from the cgroup and the descriptor count. Never filesystem limits.
    pub fn observed_controls(&self) -> BTreeSet<ConfinementControl> {
        let groups: [(ConfinementControl, fn(StateItem) -> bool); 5] = [
            (ConfinementControl::AccountIdentity, |item| {
                matches!(item, StateItem::Uid | StateItem::Gid)
            }),
            (ConfinementControl::ProcessIdentity, |item| {
                matches!(item, StateItem::Capabilities | StateItem::NoNewPrivs)
            }),
            (ConfinementControl::SyscallRestrictions, |item| {
                matches!(item, StateItem::Seccomp | StateItem::NoNewPrivs)
            }),
            (ConfinementControl::OsRestrictions, |item| {
                matches!(item, StateItem::NetworkInterfaces | StateItem::PidNamespace)
            }),
            (ConfinementControl::ResourceControls, |item| {
                matches!(
                    item,
                    StateItem::Cgroup | StateItem::CgroupLimit { .. } | StateItem::OpenDescriptors
                )
            }),
        ];
        groups
            .into_iter()
            .filter(|(_, wanted)| self.all_passed(wanted))
            .map(|(control, _)| control)
            .collect()
    }
}

fn check(item: StateItem, expected: String, observed: String, passed: bool) -> StateCheck {
    StateCheck {
        item,
        expected,
        observed,
        passed,
    }
}

/// Compares the observed state with the expected one, item by item.
pub fn compare(expected: &ExpectedLinuxState, observed: &ObservedLinuxState) -> LinuxStateReport {
    let status = &observed.status;
    let identity = expected.identity;
    let mut checks = vec![
        check(
            StateItem::Uid,
            format!("{0} {0} {0} {0}", identity.uid),
            status.uid.to_string(),
            status.uid.all_equal(identity.uid),
        ),
        check(
            StateItem::Gid,
            format!("{0} {0} {0} {0}", identity.gid),
            status.gid.to_string(),
            status.gid.all_equal(identity.gid),
        ),
        check(
            StateItem::Capabilities,
            "permitted, effective and ambient empty".to_owned(),
            format!(
                "permitted {:016x}, effective {:016x}, ambient {:016x}",
                status.cap_permitted, status.cap_effective, status.cap_ambient
            ),
            status.cap_permitted == 0 && status.cap_effective == 0 && status.cap_ambient == 0,
        ),
        check(
            StateItem::NoNewPrivs,
            "1".to_owned(),
            u8::from(status.no_new_privs).to_string(),
            status.no_new_privs,
        ),
        check(
            StateItem::Seccomp,
            SeccompMode::Filter.number().to_string(),
            status.seccomp.number().to_string(),
            status.seccomp == SeccompMode::Filter,
        ),
        check(
            StateItem::PidNamespace,
            "PID 1 of a nested PID namespace".to_owned(),
            status
                .namespace_pids
                .iter()
                .map(u32::to_string)
                .collect::<Vec<String>>()
                .join(" "),
            status.namespace_pids.len() >= 2 && status.namespace_pids.last() == Some(&1),
        ),
    ];
    let expected_interfaces: BTreeSet<&str> = expected
        .network_interfaces
        .iter()
        .map(InterfaceName::as_str)
        .collect();
    let observed_interfaces: BTreeSet<&str> = observed
        .network_interfaces
        .iter()
        .map(String::as_str)
        .collect();
    checks.push(check(
        StateItem::NetworkInterfaces,
        expected_interfaces
            .iter()
            .copied()
            .collect::<Vec<&str>>()
            .join(", "),
        observed_interfaces
            .iter()
            .copied()
            .collect::<Vec<&str>>()
            .join(", "),
        expected_interfaces == observed_interfaces,
    ));
    let cgroup = format!("/{}", expected.cgroup);
    checks.push(check(
        StateItem::Cgroup,
        cgroup.clone(),
        observed.cgroup.clone(),
        observed.cgroup == cgroup,
    ));
    for limit in &expected.cgroup_limits {
        let found = observed.cgroup_files.get(limit.file.tag());
        checks.push(check(
            StateItem::CgroupLimit { file: limit.file },
            limit.value.clone(),
            found.cloned().unwrap_or_else(|| "absent".to_owned()),
            found == Some(&limit.value),
        ));
    }
    checks.push(check(
        StateItem::OpenDescriptors,
        format!("at most {}", expected.max_open_descriptors),
        observed.open_descriptors.to_string(),
        observed.open_descriptors <= u64::from(expected.max_open_descriptors),
    ));
    LinuxStateReport { checks }
}

/// Compares a host observation that is current at `now` under `configuration` and no
/// older than `max_age`; a stale observation, or one made under another configuration,
/// is refused before any check (VM-P50 line 2825: a stale probe cannot become a pass).
pub fn check_observation(
    expected: &ExpectedLinuxState,
    observed: &HostObserved<ObservedLinuxState>,
    now: ClockReading,
    max_age: Duration,
    configuration: ConfigurationFingerprint,
) -> Result<LinuxStateReport, ObservationProblem> {
    observed.current_at(now, max_age, configuration)?;
    Ok(compare(expected, observed.value()))
}

#[cfg(test)]
pub(super) mod fixtures {
    use super::super::status::{fixtures as status, parse_status};
    use super::super::LaunchPlan;
    use super::*;

    /// What the host observes for `plan` when the jail works: the jailed status text with
    /// the plan's identity, the expected interfaces, cgroup and limits, and few
    /// descriptors.
    pub(in super::super) fn jailed(plan: &LaunchPlan) -> ObservedLinuxState {
        let expected = plan.expected_state();
        ObservedLinuxState {
            status: parse_status(status::JAILED).unwrap(),
            network_interfaces: expected
                .network_interfaces
                .iter()
                .map(|name| name.as_str().to_owned())
                .collect(),
            cgroup: format!("/{}", expected.cgroup),
            cgroup_files: expected
                .cgroup_limits
                .iter()
                .map(|limit| (limit.file.tag().to_owned(), limit.value.clone()))
                .chain([("cpu.weight".to_owned(), "100".to_owned())])
                .collect(),
            open_descriptors: 31,
        }
    }

    /// The same launch without the jail: root, the host's namespaces and interfaces, the
    /// user's own cgroup without limits, and many descriptors.
    pub(in super::super) fn unjailed() -> ObservedLinuxState {
        ObservedLinuxState {
            status: parse_status(status::UNJAILED).unwrap(),
            network_interfaces: ["lo", "eth0", "wlan0"]
                .into_iter()
                .map(str::to_owned)
                .collect(),
            cgroup: "/user.slice/user-1000.slice/session-2.scope".to_owned(),
            cgroup_files: [("memory.max".to_owned(), "max".to_owned())]
                .into_iter()
                .collect(),
            open_descriptors: 412,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::fixtures as plan_fixtures;
    use super::fixtures::{jailed, unjailed};
    use super::*;
    use crate::foundation::evidence::ProbeRegistry;
    use crate::foundation::ids::ManualClock;
    use std::sync::Arc;

    #[test]
    fn a_working_jail_passes_every_check() {
        let plan = plan_fixtures::plan();
        let report = compare(plan.expected_state(), &jailed(&plan));
        assert!(report.passed(), "{:?}", report.failed());
        assert_eq!(report.checks().len(), 12);
        assert_eq!(
            report.observed_controls(),
            [
                ConfinementControl::AccountIdentity,
                ConfinementControl::ProcessIdentity,
                ConfinementControl::SyscallRestrictions,
                ConfinementControl::OsRestrictions,
                ConfinementControl::ResourceControls,
            ]
            .into_iter()
            .collect()
        );
        assert!(!report
            .observed_controls()
            .contains(&ConfinementControl::FilesystemLimits));
    }

    #[test]
    fn the_positive_control_reports_every_difference_of_an_unjailed_launch() {
        let plan = plan_fixtures::plan();
        let report = compare(plan.expected_state(), &unjailed());
        assert!(!report.passed());
        let failed: Vec<StateItem> = report.failed().iter().map(|check| check.item).collect();
        assert_eq!(
            failed,
            [
                StateItem::Uid,
                StateItem::Gid,
                StateItem::Capabilities,
                StateItem::NoNewPrivs,
                StateItem::Seccomp,
                StateItem::PidNamespace,
                StateItem::NetworkInterfaces,
                StateItem::Cgroup,
                StateItem::CgroupLimit {
                    file: CgroupFile::CpuMax
                },
                StateItem::CgroupLimit {
                    file: CgroupFile::MemoryMax
                },
                StateItem::CgroupLimit {
                    file: CgroupFile::PidsMax
                },
                StateItem::OpenDescriptors,
            ]
        );
        assert!(report.observed_controls().is_empty());
        let seccomp = &report.failed()[4];
        assert_eq!(
            seccomp.to_string(),
            "seccomp mode: expected 2, observed 0 (fail)"
        );
        let memory = &report.failed()[9];
        assert_eq!(memory.expected, "1140850688");
        assert_eq!(memory.observed, "max");
        let cpu = &report.failed()[8];
        assert_eq!(cpu.observed, "absent");
    }

    #[test]
    fn each_rule_fails_alone_and_withdraws_its_control() {
        let plan = plan_fixtures::plan();
        let expected = plan.expected_state();
        let cases: Vec<(
            Box<dyn Fn(&mut ObservedLinuxState)>,
            StateItem,
            ConfinementControl,
        )> = vec![
            (
                Box::new(|o| o.status.uid.effective = 0),
                StateItem::Uid,
                ConfinementControl::AccountIdentity,
            ),
            (
                Box::new(|o| o.status.gid.saved = 64002),
                StateItem::Gid,
                ConfinementControl::AccountIdentity,
            ),
            (
                Box::new(|o| o.status.cap_ambient = 1 << 12),
                StateItem::Capabilities,
                ConfinementControl::ProcessIdentity,
            ),
            (
                Box::new(|o| o.status.no_new_privs = false),
                StateItem::NoNewPrivs,
                ConfinementControl::SyscallRestrictions,
            ),
            (
                Box::new(|o| o.status.seccomp = SeccompMode::Strict),
                StateItem::Seccomp,
                ConfinementControl::SyscallRestrictions,
            ),
            (
                Box::new(|o| o.status.namespace_pids = vec![48211]),
                StateItem::PidNamespace,
                ConfinementControl::OsRestrictions,
            ),
            (
                Box::new(|o| o.status.namespace_pids = vec![48211, 7]),
                StateItem::PidNamespace,
                ConfinementControl::OsRestrictions,
            ),
            (
                Box::new(|o| {
                    o.network_interfaces.insert("eth0".to_owned());
                }),
                StateItem::NetworkInterfaces,
                ConfinementControl::OsRestrictions,
            ),
            (
                Box::new(|o| {
                    o.network_interfaces.remove("lo");
                }),
                StateItem::NetworkInterfaces,
                ConfinementControl::OsRestrictions,
            ),
            (
                Box::new(|o| o.cgroup = "/yougori/firecracker".to_owned()),
                StateItem::Cgroup,
                ConfinementControl::ResourceControls,
            ),
            (
                Box::new(|o| {
                    o.cgroup_files.remove("pids.max");
                }),
                StateItem::CgroupLimit {
                    file: CgroupFile::PidsMax,
                },
                ConfinementControl::ResourceControls,
            ),
            (
                Box::new(|o| {
                    o.cgroup_files
                        .insert("cpu.max".to_owned(), "max 100000".to_owned());
                }),
                StateItem::CgroupLimit {
                    file: CgroupFile::CpuMax,
                },
                ConfinementControl::ResourceControls,
            ),
            (
                Box::new(|o| o.open_descriptors = 129),
                StateItem::OpenDescriptors,
                ConfinementControl::ResourceControls,
            ),
        ];
        for (change, item, control) in cases {
            let mut observed = jailed(&plan);
            change(&mut observed);
            let report = compare(expected, &observed);
            let failed: Vec<StateItem> = report.failed().iter().map(|check| check.item).collect();
            assert_eq!(failed, [item]);
            assert!(!report.observed_controls().contains(&control), "{item}");
        }
        let mut at_limit = jailed(&plan);
        at_limit.open_descriptors = 128;
        assert!(compare(expected, &at_limit).passed());
    }

    #[test]
    fn a_declared_interface_is_expected_beside_lo() {
        let plan = plan_fixtures::network_plan();
        let names: Vec<&str> = plan
            .expected_state()
            .network_interfaces
            .iter()
            .map(InterfaceName::as_str)
            .collect();
        assert_eq!(names, ["lo", "tap0"]);
        assert!(compare(plan.expected_state(), &jailed(&plan)).passed());
        let only_lo = jailed(&plan_fixtures::plan());
        let report = compare(plan.expected_state(), &only_lo);
        assert!(report
            .failed()
            .iter()
            .any(|check| check.item == StateItem::NetworkInterfaces));
        let strict = plan_fixtures::plan();
        let names: Vec<&str> = strict
            .expected_state()
            .network_interfaces
            .iter()
            .map(InterfaceName::as_str)
            .collect();
        assert_eq!(names, ["lo"]);
    }

    #[test]
    fn only_a_current_host_observation_is_compared() {
        let plan = plan_fixtures::plan();
        let clock = Arc::new(ManualClock::default());
        let registry = ProbeRegistry::new(Arc::clone(&clock));
        let configuration = ConfigurationFingerprint::from_settings([("host", "a")]).unwrap();
        let minute = Duration::from_secs(60);
        let observed = HostObserved::stamp(jailed(&plan), registry.now(), minute, configuration);
        let report = check_observation(
            plan.expected_state(),
            &observed,
            registry.now(),
            minute,
            configuration,
        )
        .unwrap();
        assert!(report.passed());

        let other = ConfigurationFingerprint::from_settings([("host", "b")]).unwrap();
        assert!(matches!(
            check_observation(
                plan.expected_state(),
                &observed,
                registry.now(),
                minute,
                other
            ),
            Err(ObservationProblem::OtherConfiguration { .. })
        ));
        clock.advance(Duration::from_secs(61));
        assert!(matches!(
            check_observation(
                plan.expected_state(),
                &observed,
                registry.now(),
                minute,
                configuration
            ),
            Err(ObservationProblem::Stale { .. })
        ));
    }
}
