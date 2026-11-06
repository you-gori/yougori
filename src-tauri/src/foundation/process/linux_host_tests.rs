//! Tests of the Linux host process handle over real processes (busybox `sleep` and `sh`), in
//! groups beneath a base of their own (`yougori-test`). They need root and a writable cgroup
//! v2 mount, as the disposable WSL distro of 31 October 2026 has, so they are ignored
//! elsewhere and run there with `--ignored`.

use std::fs;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use super::super::{
    end_leftover_groups, Escalation, HostProcess, LinuxContainment, NoProof, ProcessIdentity,
    ProcessRole, RunAs,
};
use crate::foundation::coordination::VmInstanceId;
use crate::foundation::ids::{digest, ExecutionId, SandboxBootGeneration};

const NEEDS: &str = "needs root and a writable cgroup v2 mount (the disposable WSL distro)";

fn use_test_base() {
    // SAFETY of the call aside (edition 2021), every test sets the same value.
    std::env::set_var("YOUGORI_CGROUP_BASE", "yougori-test");
}

fn role(name: &str) -> ProcessRole {
    let execution = ExecutionId::new(name).unwrap();
    ProcessRole::VmHost {
        vm: VmInstanceId::new(digest("yougori/test/vm/v1", &[name.as_bytes()])),
        execution,
        boot: SandboxBootGeneration::FIRST,
    }
}

fn kill_now() -> Escalation {
    Escalation {
        grace: Duration::ZERO,
        kill_wait: Duration::from_secs(10),
    }
}

fn shell(script: &str) -> Command {
    let mut command = Command::new("/bin/sh");
    command
        .args(["-c", script])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    command
}

fn wait_until(mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(20);
    while !done() {
        assert!(Instant::now() < deadline, "timed out");
        thread::sleep(Duration::from_millis(10));
    }
}

/// PROVES a process runs in a group of its own beneath the host's base from its first
/// instruction, is named by its PID and start time, has no proof while it runs, and is
/// ended through its group with the host's proof (SIGKILL reads as 137); afterwards its
/// identity no longer runs and its group is gone with the handle.
#[test]
#[ignore = "needs root and a writable cgroup v2 mount (the disposable WSL distro)"]
fn a_process_runs_in_its_own_group_and_ends_through_it() {
    let _ = NEEDS;
    use_test_base();
    let process = HostProcess::spawn(&mut shell("exec sleep 30"), role("exe-linux-a")).unwrap();
    let identity = process.identity();
    assert_eq!(
        ProcessIdentity::holder_of(identity.pid).unwrap(),
        Some(identity)
    );
    assert!(identity.running().unwrap());
    let group = process.group_path().to_path_buf();
    let membership = fs::read_to_string(format!("/proc/{}/cgroup", identity.pid)).unwrap();
    let relative = group.strip_prefix("/sys/fs/cgroup").unwrap();
    assert_eq!(membership.trim(), format!("0::/{}", relative.display()));
    assert!(matches!(process.check_ended(), Err(NoProof::StillRunning)));
    let proof = process.terminate(kill_now()).unwrap();
    assert_eq!(proof.exit_code(), 137);
    assert!(!identity.running().unwrap());
    drop(process);
    assert!(!group.exists(), "the group goes with the handle");
}

/// PROVES a process whose own program ended has no proof while a process it started still
/// runs in its group, and that killing the group ends both, with the proof.
#[test]
#[ignore = "needs root and a writable cgroup v2 mount (the disposable WSL distro)"]
fn a_child_still_alive_means_no_proof_until_the_group_is_killed() {
    use_test_base();
    let process = HostProcess::spawn(&mut shell("sleep 30 & exit 0"), role("exe-linux-b")).unwrap();
    wait_until(|| matches!(process.check_ended(), Err(NoProof::JobStillActive { .. })));
    match process.check_ended() {
        Err(NoProof::JobStillActive { exit_code, active }) => {
            assert_eq!(exit_code, 0);
            assert_eq!(active, 1);
        }
        other => panic!("{other:?}"),
    }
    let proof = process.terminate(kill_now()).unwrap();
    assert_eq!(
        proof.exit_code(),
        0,
        "the main process had exited on its own"
    );
}

/// PROVES a contained start's limits hold: the group refuses processes past `pids.max` and
/// ends the group's memory past `memory.max` (the OOM killer within the group); and the
/// process starts with no network (its own namespace's interfaces, as `/proc/self/net/dev`
/// lists them: sysfs shows the namespace that mounted it), unprivileged, with no new
/// privileges and in a session of its own.
#[test]
#[ignore = "needs root and a writable cgroup v2 mount (the disposable WSL distro)"]
fn a_contained_start_holds_its_limits_and_runs_unprivileged_without_network() {
    use_test_base();
    let containment = LinuxContainment {
        memory_limit_bytes: 32 << 20,
        max_processes: 4,
        run_as: Some(RunAs {
            uid: 65534,
            gid: 65534,
            groups: Vec::new(),
        }),
        no_network: true,
        end_with_host: false,
        drop_capabilities: true,
        nice: Some(5),
    };
    // Six sleeps on four processes: forks fail past the limit.
    let pids = HostProcess::spawn_contained(
        &mut shell("for i in 1 2 3 4 5 6; do sleep 5 & done; wait"),
        role("exe-linux-c"),
        &containment,
    )
    .unwrap();
    wait_until(|| {
        fs::read_to_string(pids.group_path().join("pids.events"))
            .unwrap()
            .lines()
            .any(|line| line.starts_with("max ") && line != "max 0")
    });
    assert!(pids.usage().unwrap().total_processes <= 4);
    pids.terminate(kill_now()).unwrap();
    // 100 MB held in the shell's own memory (a command substitution keeps its whole
    // output): past 32 MiB the group's OOM killer ends it.
    let memory = HostProcess::spawn_contained(
        &mut shell("v=$(head -c 100000000 /dev/zero | tr '\\0' a); echo ${#v}"),
        role("exe-linux-d"),
        &containment,
    )
    .unwrap();
    let proof = memory.terminate(Escalation {
        grace: Duration::from_secs(20),
        kill_wait: Duration::from_secs(10),
    });
    assert!(proof.is_ok(), "{proof:?}");
    let events = fs::read_to_string(memory.group_path().join("memory.events")).unwrap();
    let oom_kills = events
        .lines()
        .find_map(|line| line.strip_prefix("oom_kill "))
        .and_then(|value| value.trim().parse::<u64>().ok())
        .unwrap();
    assert!(oom_kills >= 1, "{events}");
    assert!(memory.usage().unwrap().peak_committed_bytes <= 33 << 20);
    // What the contained process sees of itself.
    let out = std::env::temp_dir().join(format!("yougori-contained-{}.txt", std::process::id()));
    let file = fs::File::create(&out).unwrap();
    let mut command = Command::new("/bin/sh");
    command
        .args([
            "-c",
            "grep -E '^(Uid|Gid|NoNewPrivs|CapEff|CapBnd):' /proc/self/status; \
             tail -n +3 /proc/self/net/dev | cut -d: -f1 | tr -d ' '; \
             echo \"session $(cut -d' ' -f6 /proc/self/stat) self $$\"; \
             echo \"nice $(cut -d' ' -f19 /proc/self/stat)\"",
        ])
        .stdin(Stdio::null())
        .stdout(file)
        .stderr(Stdio::null());
    let process =
        HostProcess::spawn_contained(&mut command, role("exe-linux-e"), &containment).unwrap();
    process.wait_ended(Duration::from_secs(10)).unwrap();
    let seen = fs::read_to_string(&out).unwrap();
    let _ = fs::remove_file(&out);
    assert!(seen.contains("Uid:\t65534\t65534\t65534\t65534"), "{seen}");
    assert!(seen.contains("Gid:\t65534\t65534\t65534\t65534"), "{seen}");
    assert!(seen.contains("NoNewPrivs:\t1"), "{seen}");
    assert!(seen.contains("CapEff:\t0000000000000000"), "{seen}");
    assert!(seen.contains("CapBnd:\t0000000000000000"), "{seen}");
    assert!(seen.lines().any(|line| line == "nice 5"), "{seen}");
    let interfaces: Vec<&str> = seen
        .lines()
        .filter(|line| {
            !line.contains(':') && !line.starts_with("session ") && !line.starts_with("nice ")
        })
        .collect();
    assert_eq!(interfaces, vec!["lo"], "{seen}");
    // The shell leads the session it was started in (its session id is its own PID).
    let session = seen
        .lines()
        .find_map(|line| line.strip_prefix("session "))
        .unwrap();
    let (id, own) = session.split_once(" self ").unwrap();
    assert_eq!(id, own, "{seen}");
}

/// PROVES a group an earlier host left (no handle was dropped: it died) is found beneath the
/// base by the next one, its processes ended and the group removed; a group of the current
/// host, and one of another host that still runs, are left alone.
#[test]
#[ignore = "needs root and a writable cgroup v2 mount (the disposable WSL distro)"]
fn the_next_host_ends_the_groups_an_earlier_one_left() {
    use_test_base();
    let base = std::path::PathBuf::from("/sys/fs/cgroup/yougori-test");
    fs::create_dir_all(&base).unwrap();
    // A host that no longer runs: no process has PID 999999 with start time 1.
    let left = base.join("p-999999-1-1");
    let _ = fs::remove_dir(&left);
    fs::create_dir(&left).unwrap();
    let mut orphan = Command::new("sleep").arg("30").spawn().unwrap();
    fs::write(left.join("cgroup.procs"), orphan.id().to_string()).unwrap();
    // Another host that still runs.
    let mut other_host = Command::new("sleep").arg("30").spawn().unwrap();
    let other = ProcessIdentity::holder_of(other_host.id())
        .unwrap()
        .unwrap();
    let live = base.join(format!("p-{}-{}-1", other.pid, other.start_time_ticks));
    fs::create_dir(&live).unwrap();
    let own = HostProcess::spawn(&mut shell("exec sleep 30"), role("exe-linux-f")).unwrap();
    let (removed, kept) = end_leftover_groups();
    assert!(
        removed.contains(&"p-999999-1-1".to_owned()),
        "{removed:?} {kept:?}"
    );
    assert!(!left.exists());
    let status = orphan.wait().unwrap();
    use std::os::unix::process::ExitStatusExt;
    assert_eq!(status.signal(), Some(9));
    assert!(
        own.identity().running().unwrap(),
        "the current host's own group is left alone"
    );
    assert!(live.exists(), "a live host's group is left alone");
    own.terminate(kill_now()).unwrap();
    fs::remove_dir(&live).unwrap();
    other_host.kill().unwrap();
    other_host.wait().unwrap();
}

/// PROVES only a group of the host's naming directly beneath the base is taken for a
/// process's own group (`leave_own_group` removes nothing else): a deeper group, another
/// base's group, a name of another form and a cgroup v1 line are not.
#[test]
fn only_a_group_of_the_hosts_naming_beneath_the_base_is_ones_own() {
    let base = std::path::Path::new("/sys/fs/cgroup/yougori");
    assert_eq!(
        super::own_group_in("0::/yougori/p-350-15856745-2\n", base),
        Some(base.join("p-350-15856745-2"))
    );
    for other in [
        "0::/yougori/p-350-15856745-2/inner\n",
        "0::/elsewhere/p-350-15856745-2\n",
        "0::/yougori/session-3.scope\n",
        "0::/yougori\n",
        "0::/\n",
        "1:name=systemd:/yougori/p-350-15856745-2\n",
    ] {
        assert_eq!(super::own_group_in(other, base), None, "{other:?}");
    }
}

/// PROVES a process started as root with no capability (the lifetime supervisor's
/// containment) can leave its group for the root group and remove the group, the steps of
/// `leave_own_group` at its orderly end, so nothing is left behind; and that the host still
/// proves its end with the group gone (a removed group holds no process).
#[test]
#[ignore = "needs root and a writable cgroup v2 mount (the disposable WSL distro)"]
fn a_capability_less_process_leaves_and_removes_its_own_group() {
    use_test_base();
    let containment = LinuxContainment {
        memory_limit_bytes: 32 << 20,
        max_processes: 4,
        run_as: None,
        no_network: true,
        end_with_host: false,
        drop_capabilities: true,
        nice: None,
    };
    let steps = "grep -q '^CapEff:[[:space:]]*0000000000000000$' /proc/self/status || exit 3; \
                 group=$(sed -n 's/^0:://p' /proc/self/cgroup); \
                 echo $$ > /sys/fs/cgroup/cgroup.procs || exit 4; \
                 rmdir \"/sys/fs/cgroup$group\" || exit 5";
    let process =
        HostProcess::spawn_contained(&mut shell(steps), role("exe-linux-g"), &containment).unwrap();
    let group = process.group_path().to_path_buf();
    let proof = process.wait_ended(Duration::from_secs(10)).unwrap();
    assert_eq!(proof.exit_code(), 0, "the steps failed");
    assert!(!group.exists(), "the process removed its own group");
}
