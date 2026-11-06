//! The Linux comparator of the QEMU profile (module notes in `linux.rs`).

use std::sync::Arc;
use std::time::Duration;

use super::*;
use crate::foundation::evidence::ProbeRegistry;
use crate::foundation::ids::ManualClock;
use crate::sandbox::firecracker::IdQuad;

const GIB: u64 = 1024 * 1024 * 1024;

fn config() -> ConfigurationFingerprint {
    ConfigurationFingerprint::from_settings([("host", "linux")]).unwrap()
}

fn restrictions() -> LinuxHostRestrictions {
    LinuxHostRestrictions {
        internet: false,
        memory_limit_bytes: GIB,
        max_tasks: MAX_QEMU_TASKS,
    }
}

fn ids(id: u32) -> IdQuad {
    IdQuad {
        real: id,
        effective: id,
        saved: id,
        filesystem: id,
    }
}

fn confined() -> LinuxObservedState {
    LinuxObservedState {
        status: ProcStatus {
            pid: 4242,
            uid: ids(65534),
            gid: ids(65534),
            namespace_pids: vec![4242],
            cap_permitted: 0,
            cap_effective: 0,
            cap_ambient: 0,
            no_new_privs: true,
            seccomp: SeccompMode::Filter,
        },
        cgroup: "/yougori/p-1-1".to_owned(),
        memory_max: Some(GIB),
        pids_max: Some(u64::from(MAX_QEMU_TASKS)),
        network_interfaces: ["lo".to_owned()].into_iter().collect(),
        host_uid: 1000,
    }
}

fn check(state: LinuxObservedState) -> LinuxCheck {
    let clock = Arc::new(ManualClock::default());
    let registry = ProbeRegistry::new(Arc::clone(&clock));
    let observed = HostObserved::stamp(state, registry.now(), Duration::from_secs(60), config());
    check_linux(
        &restrictions(),
        &observed,
        registry.now(),
        Duration::from_secs(60),
        config(),
    )
    .unwrap()
}

/// PROVES a process confined as the profile applies it shows every Linux control in place.
#[test]
fn a_confined_qemu_shows_every_linux_control() {
    let checked = check(confined());
    assert!(checked.passed(), "{:?}", checked.findings());
    assert_eq!(
        checked.controls_observed(),
        LINUX_CONTROLS.into_iter().collect()
    );
}

/// PROVES each restriction missing is a finding that breaks exactly its control, so a launch
/// requiring that control is refused: root, the host's own account, ids that differ, new
/// privileges, no seccomp filter, a capability, the root cgroup, a missing or other limit,
/// a network interface.
#[test]
fn each_missing_restriction_breaks_its_control() {
    let cases: Vec<(Box<dyn Fn(&mut LinuxObservedState)>, ConfinementControl)> = vec![
        (
            Box::new(|s| s.status.uid = ids(0)),
            ConfinementControl::AccountIdentity,
        ),
        (
            Box::new(|s| s.host_uid = 65534),
            ConfinementControl::AccountIdentity,
        ),
        (
            Box::new(|s| s.status.uid.saved = 0),
            ConfinementControl::AccountIdentity,
        ),
        (
            Box::new(|s| s.status.no_new_privs = false),
            ConfinementControl::ProcessIdentity,
        ),
        (
            Box::new(|s| s.status.cap_effective = 1 << 21),
            ConfinementControl::ProcessIdentity,
        ),
        (
            Box::new(|s| s.status.seccomp = SeccompMode::Disabled),
            ConfinementControl::SyscallRestrictions,
        ),
        (
            Box::new(|s| s.cgroup = "/".to_owned()),
            ConfinementControl::ResourceControls,
        ),
        (
            Box::new(|s| s.memory_max = None),
            ConfinementControl::ResourceControls,
        ),
        (
            Box::new(|s| s.pids_max = Some(1000)),
            ConfinementControl::ResourceControls,
        ),
        (
            Box::new(|s| {
                s.network_interfaces.insert("eth0".to_owned());
            }),
            ConfinementControl::OsRestrictions,
        ),
    ];
    for (change, control) in cases {
        let mut state = confined();
        change(&mut state);
        let checked = check(state);
        assert!(!checked.passed());
        let observed = checked.controls_observed();
        assert!(
            !observed.contains(&control),
            "{control:?} still observed: {:?}",
            checked.findings()
        );
        assert_eq!(
            observed.len(),
            LINUX_CONTROLS.len() - 1,
            "{:?}",
            checked.findings()
        );
    }
}

/// PROVES the readers of `/proc/<pid>/net/dev` and of a cgroup limit file.
#[test]
fn net_dev_and_limits_read_strictly() {
    let net_dev = "Inter-|   Receive                            |  Transmit\n face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n    lo:       0       0    0    0    0     0          0         0        0       0    0    0    0     0       0          0\n";
    assert_eq!(
        interfaces_of(net_dev),
        ["lo".to_owned()].into_iter().collect()
    );
    assert_eq!(limit_of("max\n"), None);
    assert_eq!(limit_of("1073741824\n"), Some(GIB));
}
