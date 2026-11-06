//! The Windows side of the adopted lifetimes (module notes in `lifetime.rs`): handles the
//! starter duplicated into this holder, each checked before it is taken.

use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::System::Threading::GetProcessId;

use super::super::handle::{SharedHandles, KILLED_EXIT_CODE, KILL_ROUNDS};
use super::super::identity::ProcessIdentity;
use super::super::proof::NoProof;
use super::super::windows_host::{creation_ticks, in_job, kill_job, observe_end};
use super::{AdoptRefusal, LifetimeEnded};

/// The identity of the process behind `handle`, read through it.
fn identity_of(handle: HANDLE) -> Option<ProcessIdentity> {
    // SAFETY: GetProcessId reads an open handle; a value that is no process handle fails.
    let pid = unsafe { GetProcessId(handle) };
    if pid == 0 {
        return None;
    }
    Some(ProcessIdentity {
        pid,
        start_time_ticks: creation_ticks(handle)?,
    })
}

/// Checks that `raw` is a process handle of `named`.
fn check_process(raw: u64, named: ProcessIdentity) -> Result<(), AdoptRefusal> {
    let found = identity_of(raw as usize as HANDLE).ok_or(AdoptRefusal::NotAProcess)?;
    if found != named {
        return Err(AdoptRefusal::OtherProcess {
            named,
            found_pid: found.pid,
            found_start_time_ticks: found.start_time_ticks,
        });
    }
    Ok(())
}

/// A process this holder observes through a process handle handed to it, such as the
/// engine that started it.
#[derive(Debug)]
pub struct AdoptedProcess {
    handle: OwnedHandle,
    identity: ProcessIdentity,
}

impl AdoptedProcess {
    /// Takes `raw`, a process handle duplicated into this process for this holder, after
    /// checking it names `identity`.
    ///
    /// # Safety
    ///
    /// `raw` must be a handle value of this process that nothing else owns or closes, as
    /// one a starter duplicated into this holder and named over its admitted control pipe
    /// is. On a refusal nothing is taken.
    pub unsafe fn adopt(raw: u64, identity: ProcessIdentity) -> Result<Self, AdoptRefusal> {
        check_process(raw, identity)?;
        Ok(Self {
            // SAFETY: the caller hands `raw` over, and it was just read as a process
            // handle of `identity`.
            handle: unsafe { OwnedHandle::from_raw_handle(raw as usize as HANDLE) },
            identity,
        })
    }

    pub fn identity(&self) -> ProcessIdentity {
        self.identity
    }

    /// Whether the process has ended, looking once without waiting.
    pub fn ended(&self) -> bool {
        // SAFETY: the handle is open with synchronize access.
        let waited = unsafe {
            windows_sys::Win32::System::Threading::WaitForSingleObject(
                self.handle.as_raw_handle(),
                0,
            )
        };
        waited == windows_sys::Win32::Foundation::WAIT_OBJECT_0
    }
}

/// This process's own job, held through a handle its starter duplicated into it
/// ([`HostProcess::share_own_job`](super::HostProcess::share_own_job)), so the job stays
/// open while this process runs after the starter's handle closed: a holder that must
/// outlive its starter holds its own job.
#[derive(Debug)]
pub struct OwnJob {
    _job: OwnedHandle,
}

impl OwnJob {
    /// Takes `raw` after checking this process is in that job.
    ///
    /// # Safety
    ///
    /// As for [`AdoptedProcess::adopt`]: `raw` must be a handle value of this process that
    /// nothing else owns or closes. On a refusal nothing is taken.
    pub unsafe fn adopt(raw: u64) -> Result<Self, AdoptRefusal> {
        // SAFETY: GetCurrentProcess takes nothing and returns this process's pseudo-handle.
        let current = unsafe { windows_sys::Win32::System::Threading::GetCurrentProcess() };
        if in_job(current, raw as usize as HANDLE) != Some(true) {
            return Err(AdoptRefusal::NotInJob);
        }
        Ok(Self {
            // SAFETY: the caller hands `raw` over, and it was just read as this process's
            // job.
            _job: unsafe { OwnedHandle::from_raw_handle(raw as usize as HANDLE) },
        })
    }
}

/// A host process and its job, held by a holder through handles handed to it
/// (module notes).
#[derive(Debug)]
pub struct AdoptedLifetime {
    job: OwnedHandle,
    process: AdoptedProcess,
}

impl AdoptedLifetime {
    /// Takes `handles`, duplicated into this process for this holder, after checking the
    /// process handle names `identity` and the process is in the job.
    ///
    /// # Safety
    ///
    /// Both values must be handles of this process that nothing else owns or closes, as
    /// ones a starter duplicated into this holder and named over its admitted control pipe
    /// are. On a refusal nothing is taken.
    pub unsafe fn adopt(
        handles: SharedHandles,
        identity: ProcessIdentity,
    ) -> Result<Self, AdoptRefusal> {
        check_process(handles.process, identity)?;
        let job = handles.job as usize as HANDLE;
        if in_job(handles.process as usize as HANDLE, job) != Some(true) {
            return Err(AdoptRefusal::NotInJob);
        }
        // SAFETY: the caller hands both values over; the process was just read as
        // `identity` and the job as its job. Nothing can fail from here on.
        let (job, process) = unsafe {
            (
                OwnedHandle::from_raw_handle(job),
                OwnedHandle::from_raw_handle(handles.process as usize as HANDLE),
            )
        };
        Ok(Self {
            job,
            process: AdoptedProcess {
                handle: process,
                identity,
            },
        })
    }

    pub fn identity(&self) -> ProcessIdentity {
        self.process.identity
    }

    /// Looks once, without waiting: the end, if the process and every process of its job
    /// ended.
    pub fn ended(&self) -> Option<LifetimeEnded> {
        observe_end(
            self.process.handle.as_raw_handle(),
            self.job.as_raw_handle(),
            Duration::ZERO,
        )
        .ok()
        .map(|ended| LifetimeEnded {
            exit_code: Some(ended.exit_code),
            job_processes: ended.job_processes,
            kill_rounds: 0,
            elapsed: Duration::ZERO,
        })
    }

    /// Kills the whole job and waits `kill_wait` for the end to be observed, at most
    /// [`KILL_ROUNDS`] times (a process created while the first kill ran is caught by the
    /// second). Without that observation there is no end, whatever was killed.
    pub fn terminate(&self, kill_wait: Duration) -> Result<LifetimeEnded, NoProof> {
        let started = Instant::now();
        let (process, job) = (self.process.handle.as_raw_handle(), self.job.as_raw_handle());
        if let Ok(ended) = observe_end(process, job, Duration::ZERO) {
            return Ok(LifetimeEnded {
                exit_code: Some(ended.exit_code),
                job_processes: ended.job_processes,
                kill_rounds: 0,
                elapsed: started.elapsed(),
            });
        }
        let mut last = NoProof::StillRunning;
        for rounds in 1..=KILL_ROUNDS {
            let killed = kill_job(job, KILLED_EXIT_CODE);
            match observe_end(process, job, kill_wait) {
                Ok(ended) => {
                    return Ok(LifetimeEnded {
                        exit_code: Some(ended.exit_code),
                        job_processes: ended.job_processes,
                        kill_rounds: rounds,
                        elapsed: started.elapsed(),
                    })
                }
                Err(no_proof) => last = killed.err().unwrap_or(no_proof),
            }
        }
        Err(last)
    }
}
