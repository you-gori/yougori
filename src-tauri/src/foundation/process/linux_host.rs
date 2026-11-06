//! The Linux host process handle (VM part §6.4: stable process handles, never a PID; S04): a
//! pidfd and a cgroup v2 group of its own per process, the Linux counterparts of the Windows
//! process handle and job.
//!
//! - **Containment before the program runs.** The group is created and limited first
//!   (`memory.max`, `pids.max`); the child joins it between fork and exec (it writes itself
//!   into the group's `cgroup.procs`), so no instruction of the program runs outside it, and
//!   every process it starts is in the group too. It also leaves the host's session for one
//!   of its own, so neither the host's terminal hanging up nor a signal to the host's
//!   process group (an interrupt typed at its terminal) reaches it: the host alone ends it.
//!   A contained start then leaves the network (a network namespace of its own), takes its
//!   priority, empties the capability bounding set (so no capability survives the program's
//!   start, even as root), drops to an unprivileged user and group with only the listed
//!   supplementary groups, and sets no-new-privileges, in that order: once it runs it can
//!   neither write the group's files nor regain a privilege, so it cannot leave the group.
//! - **A handle, never a PID.** The host holds the child unreaped from the start (its PID is
//!   not reused while it is a zombie), opens a pidfd for it at once and observes it only
//!   through the pidfd; the identity is the PID with the start time from `/proc/<pid>/stat`.
//! - **An end is observed, never assumed:** the pidfd readable, the exit status read (a
//!   signal `n` reads as `128 + n`), and the group's `cgroup.events` saying `populated 0`.
//!   Killing writes `cgroup.kill`, which ends every process of the group at once.
//! - **No kill-on-close; the child ends with its host when asked.** A Linux group outlives
//!   its holder, so dropping the handle kills the group, waits a bounded time and removes
//!   it. A contained start that must end with the host
//!   ([`LinuxContainment::end_with_host`], a VM's hypervisor) also gets a parent-death
//!   signal, `SIGKILL`, set after the account change (which would clear it) and checked
//!   against a parent that died meanwhile; since that signal follows the thread that
//!   forked, such starts fork from one thread that never ends, so the process ends when
//!   the host's process does, by the OS, however the host ended. A group an engine that
//!   died left behind is found by name under the host's base and ended and removed by the
//!   next one ([`end_leftover_groups`]). The name carries the creating host's PID and start
//!   time, so the group of a host that still runs (another engine on the same base) is
//!   left alone, and a PID reused since is not mistaken for its host.
//!
//! The groups live beneath the host's base, `/sys/fs/cgroup/yougori` unless
//! `YOUGORI_CGROUP_BASE` names another directory of the cgroup v2 mount; the host must be
//! able to create groups there (root, or a delegated subtree) and the base's parent must
//! enable the memory and pids controllers for it.

use std::ffi::CString;
use std::fs;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{mpsc, Mutex, OnceLock, PoisonError};
use std::thread;
use std::time::{Duration, Instant};

use super::handle::{HostCall, ProcessError};
use super::identity::ProcessIdentity;
use super::proof::{Ended, NoProof};
use super::usage::JobUsage;

/// The cgroup v2 mount.
const CGROUP_ROOT: &str = "/sys/fs/cgroup";

/// The base beneath the mount when `YOUGORI_CGROUP_BASE` names none.
const DEFAULT_BASE: &str = "yougori";

/// The prefix of every group a host creates beneath its base.
const GROUP_PREFIX: &str = "p-";

/// How often the group's `cgroup.events` is read while its processes end.
const GROUP_POLL: Duration = Duration::from_millis(5);

/// How long dropping a handle waits for its group to empty before removing it.
const DROP_WAIT: Duration = Duration::from_secs(5);

/// Groups created by this host, to name each one.
static GROUPS: AtomicU64 = AtomicU64::new(0);

/// This host's own identity, which names its groups.
static OWN_IDENTITY: std::sync::OnceLock<Option<ProcessIdentity>> = std::sync::OnceLock::new();

fn own_identity() -> Option<ProcessIdentity> {
    *OWN_IDENTITY.get_or_init(|| holder_of(std::process::id()).ok().flatten())
}

/// The name of a group: the host's PID and start time, and its number.
fn group_name(host: ProcessIdentity, number: u64) -> String {
    format!(
        "{GROUP_PREFIX}{}-{}-{number}",
        host.pid, host.start_time_ticks
    )
}

/// The host a group's name names; `None` for a name of another form.
fn host_of_group(name: &str) -> Option<ProcessIdentity> {
    let mut parts = name.strip_prefix(GROUP_PREFIX)?.split('-');
    let pid = parts.next()?.parse().ok()?;
    let start_time_ticks = parts.next()?.parse().ok()?;
    parts.next()?.parse::<u64>().ok()?;
    if parts.next().is_some() {
        return None;
    }
    Some(ProcessIdentity {
        pid,
        start_time_ticks,
    })
}

/// How a process is contained on Linux beyond its own group (`HostProcess::spawn_contained`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LinuxContainment {
    /// The group's `memory.max`: every process of it together.
    pub memory_limit_bytes: u64,
    /// The group's `pids.max`.
    pub max_processes: u32,
    /// The unprivileged account the process runs as, when the host runs as root.
    pub run_as: Option<RunAs>,
    /// A network namespace of its own: no interface but a loopback that is down.
    pub no_network: bool,
    /// The process ends with this host's process (a parent-death signal from a thread that
    /// never ends; module notes). Left off for a process that must outlive the host, such
    /// as its lifetime supervisor.
    pub end_with_host: bool,
    /// Every capability leaves the bounding set before the program runs, so the program
    /// holds none, even as root (a process that stays root only to own what it ends).
    pub drop_capabilities: bool,
    /// The nice value the process runs at (lower runs first), set while the host's
    /// privilege still allows a raise.
    pub nice: Option<i32>,
}

/// An unprivileged user, its group and its only supplementary groups (such as the KVM
/// device's group).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RunAs {
    pub uid: u32,
    pub gid: u32,
    pub groups: Vec<u32>,
}

fn host_error(call: HostCall, error: &io::Error) -> ProcessError {
    ProcessError::HostCall {
        call,
        os_error: error.raw_os_error().map_or(0, |code| code.unsigned_abs()),
    }
}

fn no_proof(call: HostCall, error: &io::Error) -> NoProof {
    NoProof::HostCall {
        call,
        os_error: error.raw_os_error().map_or(0, |code| code.unsigned_abs()),
    }
}

/// The host's base directory for its groups.
pub(super) fn base() -> PathBuf {
    match std::env::var_os("YOUGORI_CGROUP_BASE") {
        Some(base) if !base.is_empty() => PathBuf::from(CGROUP_ROOT).join(base),
        _ => PathBuf::from(CGROUP_ROOT).join(DEFAULT_BASE),
    }
}

/// The start time of `pid` in clock ticks since boot (`/proc/<pid>/stat`, field 22), and
/// whether it is a zombie or dead; `None` when no process has the PID.
pub(super) fn stat_of(pid: u32) -> io::Result<Option<(u64, bool)>> {
    let text = match fs::read_to_string(format!("/proc/{pid}/stat")) {
        Ok(text) => text,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    // The command name is in parentheses and may hold anything: the fields follow the last.
    let rest = text
        .rsplit_once(')')
        .map(|(_, rest)| rest)
        .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidData))?;
    let fields: Vec<&str> = rest.split_whitespace().collect();
    // `rest` starts at field 3 (state); field 22 (starttime) is index 19.
    let state = fields.first().copied().unwrap_or("?");
    let start = fields
        .get(19)
        .and_then(|value| value.parse::<u64>().ok())
        .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidData))?;
    Ok(Some((start, matches!(state, "Z" | "X"))))
}

/// The process now holding `pid`, by its start time; `None` when no process does.
pub(super) fn holder_of(pid: u32) -> Result<Option<ProcessIdentity>, ProcessError> {
    match stat_of(pid) {
        Ok(Some((start_time_ticks, _))) => Ok(Some(ProcessIdentity {
            pid,
            start_time_ticks,
        })),
        Ok(None) => Ok(None),
        Err(error) => Err(host_error(HostCall::OpenProcess, &error)),
    }
}

/// Whether `identity` runs: its PID holds a process of its start time that is no zombie.
pub(super) fn running(identity: &ProcessIdentity) -> Result<bool, ProcessError> {
    match stat_of(identity.pid) {
        Ok(Some((start, dead))) => Ok(start == identity.start_time_ticks && !dead),
        Ok(None) => Ok(false),
        Err(error) => Err(host_error(HostCall::OpenProcess, &error)),
    }
}

/// One process's group.
#[derive(Debug)]
pub(super) struct Group {
    pub(super) path: PathBuf,
}

impl Group {
    /// The group at `path`, as a holder that did not create it finds it.
    pub(super) fn at(path: PathBuf) -> Self {
        Self { path }
    }

    /// A new group beneath the base, limited by `containment`'s limits when given.
    fn create(containment: Option<&LinuxContainment>) -> Result<Self, ProcessError> {
        let base = base();
        fs::create_dir_all(&base).map_err(|error| host_error(HostCall::CreateJob, &error))?;
        // The base passes the controllers its groups are limited by.
        let _ = fs::write(base.join("cgroup.subtree_control"), "+memory +pids");
        let host = own_identity().ok_or_else(|| {
            host_error(
                HostCall::OpenProcess,
                &io::Error::from(io::ErrorKind::NotFound),
            )
        })?;
        let path = base.join(group_name(host, GROUPS.fetch_add(1, Ordering::Relaxed) + 1));
        fs::create_dir(&path).map_err(|error| host_error(HostCall::CreateJob, &error))?;
        let group = Self { path };
        if let Some(containment) = containment {
            group
                .write("memory.max", &containment.memory_limit_bytes.to_string())
                .and_then(|()| group.write("memory.swap.max", "0").or(Ok(())))
                .and_then(|()| group.write("pids.max", &containment.max_processes.to_string()))
                .map_err(|error| host_error(HostCall::LimitJob, &error))?;
        }
        Ok(group)
    }

    fn write(&self, file: &str, value: &str) -> io::Result<()> {
        fs::write(self.path.join(file), value)
    }

    fn read(&self, file: &str) -> io::Result<String> {
        fs::read_to_string(self.path.join(file))
    }

    /// Whether a process is left in the group (`cgroup.events`). A group that is gone holds
    /// none: the kernel removes only an empty group (its own process may have left it and
    /// removed it at its orderly end, as the lifetime supervisor does: [`leave_own_group`]).
    pub(super) fn populated(&self) -> io::Result<bool> {
        match self.read("cgroup.events") {
            Ok(events) => Ok(events.lines().any(|line| line.trim() == "populated 1")),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error),
        }
    }

    pub(super) fn number(&self, file: &str) -> Option<u64> {
        self.read(file).ok()?.trim().parse().ok()
    }

    /// Ends every process of the group at once.
    pub(super) fn kill(&self) -> io::Result<()> {
        self.write("cgroup.kill", "1")
    }

    /// Removes the group once it is empty.
    fn remove(&self) -> io::Result<()> {
        fs::remove_dir(&self.path)
    }
}

/// A process the host started, with its group.
pub(super) struct Process {
    /// Held unreaped until its end is observed, so its PID names it throughout.
    child: Mutex<Child>,
    pidfd: OwnedFd,
    group: Group,
}

/// Opens a pidfd for `pid`: a child this host holds unreaped, or a process a holder names
/// and then checks through it (`lifetime`).
pub(super) fn pidfd_open(pid: u32) -> io::Result<OwnedFd> {
    let pid =
        libc::pid_t::try_from(pid).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    // SAFETY: the pidfd_open system call takes a PID and flags and returns a new descriptor
    // or -1; nothing of this process's memory is passed.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the call succeeded, so `fd` is a new descriptor owned here alone.
    Ok(unsafe {
        OwnedFd::from_raw_fd(
            i32::try_from(fd).map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?,
        )
    })
}

/// Starts `command` in a new group of its own, limited and confined by `containment` when
/// given (module notes).
fn start(
    command: &mut Command,
    containment: Option<&LinuxContainment>,
) -> Result<(Process, ProcessIdentity), ProcessError> {
    let group = Group::create(containment)?;
    let procs =
        CString::new(group.path.join("cgroup.procs").as_os_str().as_bytes()).map_err(|_| {
            ProcessError::Spawn {
                detail: "the group's path holds a NUL byte".to_owned(),
            }
        })?;
    let run_as = containment.and_then(|containment| containment.run_as.clone());
    let no_network = containment.is_some_and(|containment| containment.no_network);
    let end_with_host = containment.is_some_and(|containment| containment.end_with_host);
    let drop_capabilities = containment.is_some_and(|containment| containment.drop_capabilities);
    let nice = containment.and_then(|containment| containment.nice);
    // The highest capability number this kernel knows, read before the fork.
    let last_capability: libc::c_ulong = fs::read_to_string("/proc/sys/kernel/cap_last_cap")
        .ok()
        .and_then(|text| text.trim().parse().ok())
        .unwrap_or(63);
    let confine = containment.is_some();
    // SAFETY: getpid has no preconditions.
    let host = unsafe { libc::getpid() };
    // SAFETY: the closure runs in the child between fork and exec and makes only
    // async-signal-safe system calls on memory prepared before the fork.
    unsafe {
        command.pre_exec(move || {
            let fd = libc::open(procs.as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC);
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            let written = libc::write(fd, b"0".as_ptr().cast(), 1);
            libc::close(fd);
            if written != 1 {
                return Err(io::Error::last_os_error());
            }
            if libc::setsid() < 0 {
                return Err(io::Error::last_os_error());
            }
            if no_network && libc::unshare(libc::CLONE_NEWNET) != 0 {
                return Err(io::Error::last_os_error());
            }
            if let Some(nice) = nice {
                if libc::setpriority(libc::PRIO_PROCESS, 0, nice) != 0 {
                    return Err(io::Error::last_os_error());
                }
            }
            // Out of the bounding set while the host may still change it: at the program's
            // start nothing is granted beyond it, root's full set included.
            if drop_capabilities {
                for capability in 0..=last_capability {
                    if libc::prctl(libc::PR_CAPBSET_DROP, capability, 0, 0, 0) != 0
                        && *libc::__errno_location() != libc::EINVAL
                    {
                        return Err(io::Error::last_os_error());
                    }
                }
            }
            if let Some(run_as) = &run_as {
                if libc::setgroups(run_as.groups.len(), run_as.groups.as_ptr()) != 0
                    || libc::setgid(run_as.gid) != 0
                    || libc::setuid(run_as.uid) != 0
                {
                    return Err(io::Error::last_os_error());
                }
            }
            if confine && libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                return Err(io::Error::last_os_error());
            }
            // After the account change, which clears it; a host that died before it was
            // set would never send it, so its absence is checked.
            if end_with_host {
                if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) != 0 {
                    return Err(io::Error::last_os_error());
                }
                if libc::getppid() != host {
                    return Err(io::Error::from_raw_os_error(libc::ESRCH));
                }
            }
            Ok(())
        });
    }
    let spawned = if end_with_host {
        spawn_from_lasting_thread(command)
    } else {
        command.spawn()
    };
    let mut child = match spawned {
        Ok(child) => child,
        Err(error) => {
            let _ = group.remove();
            return Err(ProcessError::Spawn {
                detail: error.to_string(),
            });
        }
    };
    let opened = pidfd_open(child.id()).and_then(|pidfd| {
        let (start_time_ticks, _) =
            stat_of(child.id())?.ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?;
        Ok((pidfd, start_time_ticks))
    });
    let (pidfd, start_time_ticks) = match opened {
        Ok(opened) => opened,
        Err(error) => {
            let _ = group.kill();
            let _ = child.wait();
            let _ = group.remove();
            return Err(host_error(HostCall::OpenProcess, &error));
        }
    };
    let identity = ProcessIdentity {
        pid: child.id(),
        start_time_ticks,
    };
    Ok((
        Process {
            child: Mutex::new(child),
            pidfd,
            group,
        },
        identity,
    ))
}

/// What the lasting thread is handed: a command to start, and where its answer goes.
type SpawnJob = (Command, mpsc::Sender<(Command, io::Result<Child>)>);

/// The thread every start that ends with this host forks from (module notes): it never
/// ends, so the parent-death signal of what it starts follows the host's process alone.
static SPAWNER: OnceLock<Option<Mutex<mpsc::Sender<SpawnJob>>>> = OnceLock::new();

/// Starts `command` from the lasting thread and waits for it; the command is handed back.
fn spawn_from_lasting_thread(command: &mut Command) -> io::Result<Child> {
    let spawner = SPAWNER.get_or_init(|| {
        let (sender, receiver) = mpsc::channel::<SpawnJob>();
        thread::Builder::new()
            .name("yougori-lasting-spawner".to_owned())
            .spawn(move || {
                for (mut command, answer) in receiver {
                    let spawned = command.spawn();
                    let _ = answer.send((command, spawned));
                }
            })
            .ok()
            .map(|_| Mutex::new(sender))
    });
    let spawner = spawner
        .as_ref()
        .ok_or_else(|| io::Error::other("the thread that starts lasting processes could not be started"))?;
    let (answer, answered) = mpsc::channel();
    let taken = std::mem::replace(command, Command::new("/"));
    let sent = spawner
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .send((taken, answer));
    if let Err(mpsc::SendError((taken, _))) = sent {
        *command = taken;
        return Err(io::Error::other("the thread that starts lasting processes has ended"));
    }
    let (returned, spawned) = answered
        .recv()
        .map_err(|_| io::Error::other("the thread that starts lasting processes has ended"))?;
    *command = returned;
    spawned
}

/// Starts `command` in a new group of its own.
pub(super) fn spawn(command: &mut Command) -> Result<(Process, ProcessIdentity), ProcessError> {
    start(command, None)
}

/// Starts `command` in a new group of its own, limited and confined by `containment`.
pub(super) fn spawn_contained(
    command: &mut Command,
    containment: &LinuxContainment,
) -> Result<(Process, ProcessIdentity), ProcessError> {
    start(command, Some(containment))
}

/// The exit code of `status`: its code, or `128 + n` for a signal `n`.
fn code_of(status: std::process::ExitStatus) -> u32 {
    match (status.code(), status.signal()) {
        (Some(code), _) => code.unsigned_abs(),
        (None, Some(signal)) => 128 + signal.unsigned_abs(),
        (None, None) => u32::MAX,
    }
}

impl Process {
    /// Observes, within `within`, the pidfd readable, the exit status and no process left
    /// in the group.
    pub(super) fn observe(&self, within: Duration) -> Result<Ended, NoProof> {
        let started = Instant::now();
        let millis = i32::try_from(within.as_millis()).unwrap_or(i32::MAX);
        let mut poll = libc::pollfd {
            fd: self.pidfd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: one live pollfd of an open descriptor.
        let ready = unsafe { libc::poll(&mut poll, 1, millis) };
        if ready < 0 {
            return Err(no_proof(
                HostCall::WaitForProcess,
                &io::Error::last_os_error(),
            ));
        }
        if ready == 0 {
            return Err(NoProof::StillRunning);
        }
        let reaped = self
            .child
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .try_wait();
        let status = match reaped {
            Ok(Some(status)) => status,
            Ok(None) => return Err(NoProof::StillRunning),
            Err(error) => return Err(no_proof(HostCall::ReadExitCode, &error)),
        };
        let exit_code = code_of(status);
        let deadline = started + within;
        loop {
            match self.group.populated() {
                Ok(false) => {
                    let peak = self.group.number("pids.peak").unwrap_or(1);
                    return Ok(Ended {
                        exit_code,
                        job_processes: u32::try_from(peak).unwrap_or(u32::MAX).max(1),
                    });
                }
                Ok(true) => {}
                Err(error) => return Err(no_proof(HostCall::QueryJob, &error)),
            }
            let now = Instant::now();
            if now >= deadline {
                let active = self.group.number("pids.current").unwrap_or(1);
                return Err(NoProof::JobStillActive {
                    exit_code,
                    active: u32::try_from(active).unwrap_or(u32::MAX),
                });
            }
            thread::sleep(GROUP_POLL.min(deadline.saturating_duration_since(now)));
        }
    }

    /// Kills every process of the group (`cgroup.kill`; Linux carries no exit code with it:
    /// the processes read as ended by `SIGKILL`, 137).
    pub(super) fn kill(&self, _code: u32) -> Result<(), NoProof> {
        self.group
            .kill()
            .map_err(|error| no_proof(HostCall::TerminateJob, &error))
    }

    /// What the group has used: CPU time in 100-nanosecond ticks (`cpu.stat`), the processes
    /// now and at most (`pids.current`, `pids.peak`), and the peak memory (`memory.peak`).
    pub(super) fn usage(&self) -> Result<JobUsage, ProcessError> {
        let stat = self
            .group
            .read("cpu.stat")
            .map_err(|error| host_error(HostCall::ReadJobUsage, &error))?;
        let usage_usec = stat
            .lines()
            .find_map(|line| line.strip_prefix("usage_usec "))
            .and_then(|value| value.trim().parse::<u64>().ok())
            .unwrap_or(0);
        let active = self.group.number("pids.current").unwrap_or(0);
        Ok(JobUsage {
            cpu_time_ticks: usage_usec.saturating_mul(10),
            active_processes: u32::try_from(active).unwrap_or(u32::MAX),
            total_processes: u32::try_from(self.group.number("pids.peak").unwrap_or(active))
                .unwrap_or(u32::MAX),
            peak_committed_bytes: self
                .group
                .number("memory.peak")
                .or_else(|| self.group.number("memory.current"))
                .unwrap_or(0),
        })
    }

    /// The group's directory, for a reader of its files (`memory.events`, `pids.events`).
    pub(super) fn group_path(&self) -> &Path {
        &self.group.path
    }
}

impl Drop for Process {
    /// Kills the group, waits a bounded time for it to empty and the child to be reaped,
    /// and removes it: nothing the host started outlives its handle (module notes).
    fn drop(&mut self) {
        let _ = self.group.kill();
        let deadline = Instant::now() + DROP_WAIT;
        let child = self.child.get_mut().unwrap_or_else(PoisonError::into_inner);
        loop {
            let reaped = matches!(child.try_wait(), Ok(Some(_)));
            let empty = matches!(self.group.populated(), Ok(false));
            if (reaped && empty) || Instant::now() >= deadline {
                break;
            }
            thread::sleep(GROUP_POLL);
        }
        let _ = self.group.remove();
    }
}

/// The group of this host's naming, directly beneath `base`, that `/proc/<pid>/cgroup`'s text
/// (`cgroup`, the unified hierarchy's `0::/path` line) puts a process in; `None` for any
/// other group.
pub(super) fn own_group_in(cgroup: &str, base: &Path) -> Option<PathBuf> {
    let relative = cgroup.lines().find_map(|line| line.strip_prefix("0::"))?;
    let path = Path::new(CGROUP_ROOT).join(relative.trim().trim_start_matches('/'));
    let name = path.file_name()?.to_str()?;
    (path.parent() == Some(base) && host_of_group(name).is_some()).then_some(path)
}

/// Moves this process out of the group its host started it in and removes the group: the
/// last act of a process that outlives that host by design (the lifetime supervisor), so an
/// orderly end leaves no empty group behind. The process moves to the hierarchy's root group,
/// the one group that holds processes beside groups with controllers (the base passes
/// controllers to its groups, so it holds none); writing there needs no capability, only
/// the root account's ownership of the file. Only a group of this host's naming directly
/// beneath the base is left; a group still holding another process stays, and the next host
/// removes it once empty ([`end_leftover_groups`]).
pub fn leave_own_group() -> io::Result<PathBuf> {
    let cgroup = fs::read_to_string("/proc/self/cgroup")?;
    let group = own_group_in(&cgroup, &base()).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "this process is not in a group of the host's",
        )
    })?;
    fs::write(
        Path::new(CGROUP_ROOT).join("cgroup.procs"),
        std::process::id().to_string(),
    )?;
    fs::remove_dir(&group)?;
    Ok(group)
}

/// Ends and removes every group beneath the base whose host no longer runs (a host that
/// died drops no handle): kills each, waits a bounded time for it to empty and removes it.
/// A group whose host still runs, this one or another, is left alone, as is a name of
/// another form. Returns the groups removed and those that could not be.
pub fn end_leftover_groups() -> (Vec<String>, Vec<String>) {
    let mut removed = Vec::new();
    let mut left = Vec::new();
    let Ok(entries) = fs::read_dir(base()) else {
        return (removed, left);
    };
    for entry in entries.filter_map(Result::ok) {
        let name = entry.file_name().to_string_lossy().into_owned();
        let Some(host) = host_of_group(&name) else {
            continue;
        };
        // A host that cannot be looked up may still run: its group is left alone.
        if !entry.path().is_dir() || !matches!(running(&host), Ok(false)) {
            continue;
        }
        let group = Group { path: entry.path() };
        let _ = group.kill();
        let deadline = Instant::now() + DROP_WAIT;
        while matches!(group.populated(), Ok(true)) && Instant::now() < deadline {
            thread::sleep(GROUP_POLL);
        }
        match group.remove() {
            Ok(()) => removed.push(name),
            Err(_) => left.push(name),
        }
    }
    (removed, left)
}

#[cfg(test)]
#[path = "linux_host_tests.rs"]
mod tests;
