//! The Linux side of the adopted lifetimes (module notes in `lifetime.rs`): no value is
//! handed over; the holder opens its own pidfd for the named process, checks through it
//! that the PID still names that process, and finds its group while the pidfd pins it.

use std::fs;
use std::io;
use std::os::fd::{AsRawFd, OwnedFd};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use super::super::handle::{HostCall, SharedHandles, KILL_ROUNDS};
use super::super::identity::ProcessIdentity;
use super::super::linux_host::{pidfd_open, stat_of, Group};
use super::super::proof::NoProof;
use super::{AdoptRefusal, LifetimeEnded};

/// The cgroup v2 mount.
const CGROUP_ROOT: &str = "/sys/fs/cgroup";

/// How often a holder looks at the group while it waits for it to empty.
const GROUP_POLL: Duration = Duration::from_millis(5);

/// What a process ended by `SIGKILL` reads as (`128 + 9`), as the host's own proof reads
/// it: the code a holder gives an end it caused when the kernel does not tell it.
const SIGKILL_EXIT_CODE: u32 = 137;

/// `PIDFD_GET_INFO` (`_IOWR(0xFF, 11, struct pidfd_info)`, Linux 6.13) and its exit flag
/// (`PIDFD_INFO_EXIT`, Linux 6.15): any holder of a pidfd may read how the process ended.
const PIDFD_GET_INFO: u32 = 0xC048_FF0B;
const PIDFD_INFO_EXIT: u64 = 1 << 3;

/// `struct pidfd_info` as Linux 6.15 publishes it (72 bytes); the kernel writes every field,
/// this reads the mask and the exit status.
#[repr(C)]
#[derive(Default)]
#[allow(dead_code)]
struct PidfdInfo {
    mask: u64,
    cgroupid: u64,
    pid: u32,
    tgid: u32,
    ppid: u32,
    ruid: u32,
    rgid: u32,
    euid: u32,
    egid: u32,
    suid: u32,
    sgid: u32,
    fsuid: u32,
    fsgid: u32,
    exit_code: i32,
    coredump_mask: u32,
    spare: u32,
}

fn no_proof(call: HostCall, error: &io::Error) -> NoProof {
    NoProof::HostCall {
        call,
        os_error: error.raw_os_error().map_or(0, i32::unsigned_abs),
    }
}

/// Opens a pidfd for `named` and checks, through it, that the PID still names that
/// process: its start time is read after the pidfd pinned it, so a PID reused before the
/// open reads another start time and is refused.
fn open_checked(named: ProcessIdentity) -> Result<OwnedFd, AdoptRefusal> {
    let pidfd = pidfd_open(named.pid).map_err(|_| AdoptRefusal::NotAProcess)?;
    check_start(named)?;
    Ok(pidfd)
}

/// The PID's start time is still `named`'s.
fn check_start(named: ProcessIdentity) -> Result<(), AdoptRefusal> {
    match stat_of(named.pid) {
        Ok(Some((start, _))) if start == named.start_time_ticks => Ok(()),
        Ok(Some((start, _))) => Err(AdoptRefusal::OtherProcess {
            named,
            found_pid: named.pid,
            found_start_time_ticks: start,
        }),
        _ => Err(AdoptRefusal::NotAProcess),
    }
}

/// Whether the process behind `pidfd` ended, waiting at most `within`.
fn exited(pidfd: &OwnedFd, within: Duration) -> Result<bool, NoProof> {
    let millis = i32::try_from(within.as_millis()).unwrap_or(i32::MAX);
    let mut poll = libc::pollfd {
        fd: pidfd.as_raw_fd(),
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
    Ok(ready > 0)
}

/// The exit code the kernel keeps for the ended process behind `pidfd`, as the host's
/// proof writes it (a signal `n` as `128 + n`); `None` where the kernel does not tell a
/// holder that is not the parent.
fn exit_code(pidfd: &OwnedFd) -> Option<u32> {
    let mut info = PidfdInfo {
        mask: PIDFD_INFO_EXIT,
        ..PidfdInfo::default()
    };
    // SAFETY: an open pidfd and a live structure of the size the request encodes.
    let read = unsafe { libc::ioctl(pidfd.as_raw_fd(), PIDFD_GET_INFO as _, &mut info) };
    if read != 0 || info.mask & PIDFD_INFO_EXIT == 0 {
        return None;
    }
    let status = info.exit_code;
    if libc::WIFEXITED(status) {
        Some(libc::WEXITSTATUS(status).unsigned_abs())
    } else if libc::WIFSIGNALED(status) {
        Some(128 + libc::WTERMSIG(status).unsigned_abs())
    } else {
        None
    }
}

/// The group `/proc/<pid>/cgroup` names, beneath the cgroup mount; `None` for the root
/// group or a line of another form.
fn group_of(pid: u32) -> Option<PathBuf> {
    let text = fs::read_to_string(format!("/proc/{pid}/cgroup")).ok()?;
    let relative = text
        .lines()
        .find_map(|line| line.strip_prefix("0::"))?
        .trim()
        .trim_start_matches('/');
    if relative.is_empty() || relative.split('/').any(|part| part == "..") {
        return None;
    }
    Some(PathBuf::from(CGROUP_ROOT).join(relative))
}

/// A process this holder observes through a pidfd of its own, such as the engine that
/// started it.
#[derive(Debug)]
pub struct AdoptedProcess {
    pidfd: OwnedFd,
    identity: ProcessIdentity,
}

impl AdoptedProcess {
    /// Opens a pidfd for `identity` and checks it (module notes). `_raw`, the value a
    /// Windows starter duplicates, carries nothing here.
    ///
    /// # Safety
    ///
    /// Nothing is required on Linux: no value is taken; the signature is the Windows one.
    pub unsafe fn adopt(_raw: u64, identity: ProcessIdentity) -> Result<Self, AdoptRefusal> {
        Ok(Self {
            pidfd: open_checked(identity)?,
            identity,
        })
    }

    pub fn identity(&self) -> ProcessIdentity {
        self.identity
    }

    /// Whether the process has ended, looking once without waiting.
    pub fn ended(&self) -> bool {
        exited(&self.pidfd, Duration::ZERO).unwrap_or(false)
    }
}

/// Nothing to hold on Linux: a group outlives every handle, so a holder needs none of its
/// own to outlive its starter.
#[derive(Debug)]
pub struct OwnJob;

impl OwnJob {
    /// Takes nothing; `_raw` carries nothing here.
    ///
    /// # Safety
    ///
    /// Nothing is required on Linux; the signature is the Windows one.
    pub unsafe fn adopt(_raw: u64) -> Result<Self, AdoptRefusal> {
        Ok(Self)
    }
}

/// A host process and its group, held by a holder through a pidfd of its own (module
/// notes).
#[derive(Debug)]
pub struct AdoptedLifetime {
    process: AdoptedProcess,
    group: Group,
}

impl AdoptedLifetime {
    /// Opens a pidfd for `identity`, checks it, and finds the process's group, which must
    /// be one of its own beneath the cgroup mount (`AdoptRefusal::NotInJob` otherwise).
    /// The start time is read again after the group, so the group read is that process's.
    /// `_handles`, the values a Windows starter duplicates, carry nothing here.
    ///
    /// # Safety
    ///
    /// Nothing is required on Linux: no value is taken; the signature is the Windows one.
    pub unsafe fn adopt(
        _handles: SharedHandles,
        identity: ProcessIdentity,
    ) -> Result<Self, AdoptRefusal> {
        let pidfd = open_checked(identity)?;
        let group = group_of(identity.pid).ok_or(AdoptRefusal::NotInJob)?;
        check_start(identity)?;
        Ok(Self {
            process: AdoptedProcess { pidfd, identity },
            group: Group::at(group),
        })
    }

    pub fn identity(&self) -> ProcessIdentity {
        self.process.identity
    }

    /// Whether the group is empty: no process left, or the group itself gone.
    fn group_empty(&self) -> Result<bool, NoProof> {
        match self.group.populated() {
            Ok(populated) => Ok(!populated),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(true),
            Err(error) => Err(no_proof(HostCall::QueryJob, &error)),
        }
    }

    /// The end, if the process ended and its group is empty, observed within `within`.
    fn observe(&self, within: Duration, killed: bool) -> Result<LifetimeEnded, NoProof> {
        let started = Instant::now();
        if !exited(&self.process.pidfd, within)? {
            return Err(NoProof::StillRunning);
        }
        let code = exit_code(&self.process.pidfd).or(killed.then_some(SIGKILL_EXIT_CODE));
        let deadline = started + within;
        loop {
            if self.group_empty()? {
                let peak = self.group.number("pids.peak").unwrap_or(1);
                return Ok(LifetimeEnded {
                    exit_code: code,
                    job_processes: u32::try_from(peak).unwrap_or(u32::MAX).max(1),
                    kill_rounds: 0,
                    elapsed: Duration::ZERO,
                });
            }
            let now = Instant::now();
            if now >= deadline {
                let active = self.group.number("pids.current").unwrap_or(1);
                return Err(NoProof::JobStillActive {
                    exit_code: code.unwrap_or(SIGKILL_EXIT_CODE),
                    active: u32::try_from(active).unwrap_or(u32::MAX),
                });
            }
            std::thread::sleep(GROUP_POLL.min(deadline.saturating_duration_since(now)));
        }
    }

    /// Looks once, without waiting: the end, if the process and every process of its group
    /// ended.
    pub fn ended(&self) -> Option<LifetimeEnded> {
        self.observe(Duration::ZERO, false).ok()
    }

    /// Kills the whole group (`cgroup.kill`) and waits `kill_wait` for the end to be
    /// observed, at most [`KILL_ROUNDS`] times. Without that observation there is no end,
    /// whatever was killed. An end this holder caused reads as `SIGKILL`'s 137 where the
    /// kernel does not tell the code.
    pub fn terminate(&self, kill_wait: Duration) -> Result<LifetimeEnded, NoProof> {
        let started = Instant::now();
        if let Ok(ended) = self.observe(Duration::ZERO, false) {
            return Ok(LifetimeEnded {
                elapsed: started.elapsed(),
                ..ended
            });
        }
        let mut last = NoProof::StillRunning;
        for rounds in 1..=KILL_ROUNDS {
            let killed = match self.group.kill() {
                Ok(()) => Ok(()),
                // A group already removed has no process left to kill.
                Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
                Err(error) => Err(no_proof(HostCall::TerminateJob, &error)),
            };
            match self.observe(kill_wait, true) {
                Ok(ended) => {
                    return Ok(LifetimeEnded {
                        kill_rounds: rounds,
                        elapsed: started.elapsed(),
                        ..ended
                    })
                }
                Err(no_proof) => last = killed.err().unwrap_or(no_proof),
            }
        }
        Err(last)
    }
}
