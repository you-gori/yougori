//! The Windows host process handle (VM part §6.4: Job and process handles; S04).
//!
//! The child is created suspended, assigned to a new Job object that kills every process
//! in it when the job closes and permits no breakaway, checked to be in the job, and only
//! then resumed: no instruction of it runs outside the job, so every process it starts is
//! in the job too. The job and process handles are held until the value is dropped, so the
//! PID cannot be reused while held. An end is observed, never assumed: the process handle
//! signalled, the exit code read, and no active process left in the job.

use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle};
use std::os::windows::process::CommandExt;
use std::process::{Child, Command};
use std::ptr::{null, null_mut};
use std::thread;
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{
    DuplicateHandle, GetLastError, DUPLICATE_CLOSE_SOURCE, ERROR_INVALID_DATA,
    ERROR_INVALID_PARAMETER, FILETIME, HANDLE, INVALID_HANDLE_VALUE, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD, THREADENTRY32,
};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, IsProcessInJob,
    JobObjectBasicAccountingInformation, JobObjectBasicUIRestrictions,
    JobObjectExtendedLimitInformation, QueryInformationJobObject, SetInformationJobObject,
    TerminateJobObject, JOBOBJECTINFOCLASS, JOBOBJECT_BASIC_ACCOUNTING_INFORMATION,
    JOBOBJECT_BASIC_UI_RESTRICTIONS, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetExitCodeProcess, GetProcessTimes, OpenProcess, OpenThread,
    ResumeThread, TerminateProcess, WaitForSingleObject, CREATE_NO_WINDOW, CREATE_SUSPENDED,
    PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE, THREAD_SUSPEND_RESUME,
};

use super::confined::{create_suspended, Confinement};
use super::handle::{HostCall, ProcessError, SharedHandles, KILLED_EXIT_CODE};
use super::identity::ProcessIdentity;
use super::proof::{Ended, NoProof};
use super::restricted::{
    create_restricted_suspended, read_back, ReadbackError, RestrictedStart, RestrictionReadback,
    StartObservation,
};
use super::usage::JobUsage;

/// The longest single wait, in milliseconds: one below `INFINITE`, so every wait is
/// bounded.
const MAX_WAIT_MS: u32 = u32::MAX - 1;

/// How often the job's process count is read while its processes end.
const JOB_POLL: Duration = Duration::from_millis(5);

/// How long a process that failed to start properly is waited for after it was killed.
const DISCARD_WAIT_MS: u32 = 5_000;

/// The last OS error of this thread; read right after the call that failed.
fn last_error() -> u32 {
    // SAFETY: GetLastError has no preconditions.
    unsafe { GetLastError() }
}

fn spawn_error(call: HostCall) -> ProcessError {
    ProcessError::HostCall {
        call,
        os_error: last_error(),
    }
}

fn no_proof(call: HostCall) -> NoProof {
    NoProof::HostCall {
        call,
        os_error: last_error(),
    }
}

/// The size of `T` as Windows takes it. Every structure passed here is far smaller than
/// `u32::MAX`; were one not, the call would be refused for the wrong size.
fn size_u32<T>() -> u32 {
    u32::try_from(std::mem::size_of::<T>()).unwrap_or(u32::MAX)
}

/// A job information structure that [`Process::query_job`] reads whole under its class.
/// Implemented only for the windows-sys structures of their classes, which hold integers
/// alone, so any bytes the system writes into one make a valid value.
trait JobInformation: Default {
    /// The information class that reads this structure.
    const CLASS: JOBOBJECTINFOCLASS;
}

impl JobInformation for JOBOBJECT_BASIC_ACCOUNTING_INFORMATION {
    const CLASS: JOBOBJECTINFOCLASS = JobObjectBasicAccountingInformation;
}

impl JobInformation for JOBOBJECT_EXTENDED_LIMIT_INFORMATION {
    const CLASS: JOBOBJECTINFOCLASS = JobObjectExtendedLimitInformation;
}

/// Takes ownership of a handle a Windows call returned, `None` for null.
fn owned(raw: HANDLE) -> Option<OwnedHandle> {
    // SAFETY: a non-null handle a call has just returned is open and owned by nobody else.
    (!raw.is_null()).then(|| unsafe { OwnedHandle::from_raw_handle(raw) })
}

// Job object access rights (winnt.h); `Win32_System_SystemServices` is not enabled.
const JOB_OBJECT_QUERY: u32 = 0x0004;
const JOB_OBJECT_TERMINATE: u32 = 0x0008;

/// Duplicates `source`, a handle of this process, into the process `target` with
/// `access`; the value is the handle in `target`.
fn duplicate_into(source: HANDLE, target: HANDLE, access: u32) -> Result<u64, ProcessError> {
    let mut duplicated: HANDLE = null_mut();
    // SAFETY: `source` is a handle of this process (or its pseudo-handle) and `target` an
    // open process handle with duplicate access; `duplicated` is a live HANDLE written by
    // the call; no inheritance and no options.
    let ok = unsafe {
        DuplicateHandle(
            GetCurrentProcess(),
            source,
            target,
            &mut duplicated,
            access,
            0,
            0,
        )
    };
    if ok == 0 {
        return Err(spawn_error(HostCall::DuplicateHandle));
    }
    Ok(duplicated as usize as u64)
}

/// Closes `handle` in the process `target`; best effort.
fn close_in(target: HANDLE, handle: u64) {
    // SAFETY: `target` is an open process handle with duplicate access; closing a handle
    // of that process through DUPLICATE_CLOSE_SOURCE writes nothing here.
    unsafe {
        DuplicateHandle(
            target,
            handle as usize as HANDLE,
            null_mut(),
            null_mut(),
            0,
            0,
            DUPLICATE_CLOSE_SOURCE,
        );
    }
}

/// A handle to this process, duplicated into `holder`'s process (synchronize and limited
/// query access).
pub(super) fn share_current_process_with(holder: &Process) -> Result<u64, ProcessError> {
    // SAFETY: GetCurrentProcess takes nothing and returns this process's pseudo-handle,
    // which DuplicateHandle turns into a real handle in the target.
    let current = unsafe { GetCurrentProcess() };
    duplicate_into(
        current,
        holder.process_handle(),
        PROCESS_SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION,
    )
}

/// Observes, within `within`, the process handle `process` signalled, its exit code and
/// no active process left in the job `job`: a [`Process`]'s end, or a held one's
/// ([`AdoptedLifetime`](super::AdoptedLifetime)).
pub(super) fn observe_end(process: HANDLE, job: HANDLE, within: Duration) -> Result<Ended, NoProof> {
    let started = Instant::now();
    let millis = u32::try_from(within.as_millis())
        .unwrap_or(MAX_WAIT_MS)
        .min(MAX_WAIT_MS);
    let deadline = started
        .checked_add(Duration::from_millis(u64::from(millis)))
        .unwrap_or(started);
    // SAFETY: the process handle is open with synchronize access.
    match unsafe { WaitForSingleObject(process, millis) } {
        WAIT_OBJECT_0 => {}
        WAIT_TIMEOUT => return Err(NoProof::StillRunning),
        _ => return Err(no_proof(HostCall::WaitForProcess)),
    }
    let mut exit_code = 0_u32;
    // SAFETY: the process handle is open and `exit_code` is live.
    if unsafe { GetExitCodeProcess(process, &mut exit_code) } == 0 {
        return Err(no_proof(HostCall::ReadExitCode));
    }
    loop {
        let counts: JOBOBJECT_BASIC_ACCOUNTING_INFORMATION =
            query_job_handle(job).ok_or_else(|| no_proof(HostCall::QueryJob))?;
        if counts.ActiveProcesses == 0 {
            return Ok(Ended {
                exit_code,
                job_processes: counts.TotalProcesses,
            });
        }
        let now = Instant::now();
        if now >= deadline {
            return Err(NoProof::JobStillActive {
                exit_code,
                active: counts.ActiveProcesses,
            });
        }
        thread::sleep(JOB_POLL.min(deadline.saturating_duration_since(now)));
    }
}

/// Kills every process in the job `job` with `code`.
pub(super) fn kill_job(job: HANDLE, code: u32) -> Result<(), NoProof> {
    // SAFETY: the job handle is open with terminate access.
    if unsafe { TerminateJobObject(job, code) } == 0 {
        return Err(no_proof(HostCall::TerminateJob));
    }
    Ok(())
}

/// Reads the job information `T` of `job` under its class; `None` when the call failed,
/// its error left for the caller to read before any other Windows call.
fn query_job_handle<T: JobInformation>(job: HANDLE) -> Option<T> {
    let mut information = T::default();
    // SAFETY: the job handle is open and `information` is a live structure of the stated
    // size, the one `T::CLASS` reads; it holds integers alone, so whatever the call writes
    // is a valid value. The returned length is not wanted.
    let read = unsafe {
        QueryInformationJobObject(
            job,
            T::CLASS,
            (&mut information as *mut T).cast(),
            size_u32::<T>(),
            null_mut(),
        )
    };
    (read != 0).then_some(information)
}

/// Whether the process `process` is in the job `job`; `None` when the host cannot say.
pub(super) fn in_job(process: HANDLE, job: HANDLE) -> Option<bool> {
    let mut in_job = 0;
    // SAFETY: both are open handles and `in_job` is a live BOOL.
    (unsafe { IsProcessInJob(process, job, &mut in_job) } != 0).then_some(in_job != 0)
}

/// The creation time of the process behind `handle`, in 100-nanosecond ticks since 1601.
pub(super) fn creation_ticks(handle: HANDLE) -> Option<u64> {
    let mut creation = FILETIME::default();
    let (mut exit, mut kernel, mut user) = (
        FILETIME::default(),
        FILETIME::default(),
        FILETIME::default(),
    );
    // SAFETY: `handle` is an open process handle and every pointer is to a live FILETIME.
    let read = unsafe { GetProcessTimes(handle, &mut creation, &mut exit, &mut kernel, &mut user) };
    (read != 0)
        .then(|| (u64::from(creation.dwHighDateTime) << 32) | u64::from(creation.dwLowDateTime))
}

/// A new job that kills every process in it when its last handle closes. Breakaway is not
/// permitted: no limit flag allows it.
fn create_job() -> Result<OwnedHandle, ProcessError> {
    // SAFETY: both pointers may be null: default security, no name.
    let job = owned(unsafe { CreateJobObjectW(null(), null()) })
        .ok_or_else(|| spawn_error(HostCall::CreateJob))?;
    let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    // SAFETY: the job handle is open and `limits` is a live structure of the stated size.
    let set = unsafe {
        SetInformationJobObject(
            job.as_raw_handle(),
            JobObjectExtendedLimitInformation,
            (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
            size_u32::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>(),
        )
    };
    if set == 0 {
        return Err(spawn_error(HostCall::LimitJob));
    }
    Ok(job)
}

/// Resumes every thread of the suspended process `pid`. The caller holds the process
/// handle, so `pid` names that process throughout.
fn resume_threads(pid: u32) -> Result<(), ProcessError> {
    // SAFETY: a thread snapshot of the whole system takes no pointer.
    let raw = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
    if raw == INVALID_HANDLE_VALUE {
        return Err(spawn_error(HostCall::ListThreads));
    }
    let snapshot = owned(raw).ok_or_else(|| spawn_error(HostCall::ListThreads))?;
    let mut entry = THREADENTRY32 {
        dwSize: size_u32::<THREADENTRY32>(),
        ..THREADENTRY32::default()
    };
    let mut resumed = 0_u32;
    // SAFETY: the snapshot handle is open and `entry` is live with its size set.
    let mut more = unsafe { Thread32First(snapshot.as_raw_handle(), &mut entry) } != 0;
    while more {
        if entry.th32OwnerProcessID == pid {
            // SAFETY: OpenThread takes no pointer.
            let thread = owned(unsafe { OpenThread(THREAD_SUSPEND_RESUME, 0, entry.th32ThreadID) })
                .ok_or_else(|| spawn_error(HostCall::ResumeThread))?;
            // SAFETY: the thread handle is open with suspend and resume access.
            if unsafe { ResumeThread(thread.as_raw_handle()) } == u32::MAX {
                return Err(spawn_error(HostCall::ResumeThread));
            }
            resumed = resumed.saturating_add(1);
        }
        // SAFETY: as for Thread32First.
        more = unsafe { Thread32Next(snapshot.as_raw_handle(), &mut entry) } != 0;
    }
    if resumed == 0 {
        Err(ProcessError::NotResumed)
    } else {
        Ok(())
    }
}

/// Starts `command` suspended, contains it in a new job and resumes it.
pub(super) fn spawn(command: &mut Command) -> Result<(Process, ProcessIdentity), ProcessError> {
    let job = create_job()?;
    command.creation_flags(CREATE_SUSPENDED | CREATE_NO_WINDOW);
    let child = command.spawn().map_err(|error| ProcessError::Spawn {
        detail: error.to_string(),
    })?;
    start_contained(Process {
        job,
        child: Held::Started(child),
        desktop: None,
    })
}

/// The process now holding `pid`, by its creation time; `None` when no process does.
pub(super) fn holder_of(pid: u32) -> Result<Option<ProcessIdentity>, ProcessError> {
    // SAFETY: OpenProcess takes no pointer.
    let raw = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    let Some(handle) = owned(raw) else {
        let os_error = last_error();
        return if os_error == ERROR_INVALID_PARAMETER {
            Ok(None)
        } else {
            Err(ProcessError::HostCall {
                call: HostCall::OpenProcess,
                os_error,
            })
        };
    };
    let start_time_ticks = creation_ticks(handle.as_raw_handle())
        .ok_or_else(|| spawn_error(HostCall::ReadProcessTimes))?;
    Ok(Some(ProcessIdentity {
        pid,
        start_time_ticks,
    }))
}

/// Whether the process `identity` names runs: one holds its PID with its creation time and
/// has not exited (a process object an open handle keeps after its exit does not run).
pub(super) fn running(identity: &ProcessIdentity) -> Result<bool, ProcessError> {
    // SAFETY: OpenProcess takes no pointer.
    let raw = unsafe {
        OpenProcess(
            PROCESS_SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION,
            0,
            identity.pid,
        )
    };
    let Some(handle) = owned(raw) else {
        let os_error = last_error();
        return if os_error == ERROR_INVALID_PARAMETER {
            Ok(false)
        } else {
            Err(ProcessError::HostCall {
                call: HostCall::OpenProcess,
                os_error,
            })
        };
    };
    if creation_ticks(handle.as_raw_handle()) != Some(identity.start_time_ticks) {
        return Ok(false);
    }
    // SAFETY: the handle is open with synchronize access.
    Ok(unsafe { WaitForSingleObject(handle.as_raw_handle(), 0) } == WAIT_TIMEOUT)
}

/// A process the host started, with its job.
pub(super) struct Process {
    /// The job the process and every process it starts run in. Closing it kills them all.
    job: OwnedHandle,
    /// The process (and, for an ordinary start, its main thread), held for the process's
    /// life.
    child: Held,
    /// The desktop a restricted process was started on, held for the process's life:
    /// Windows destroys a desktop once its last handle closes and no process is on it, and
    /// a process just resumed has not attached yet, so dropping the handle at the start
    /// would end the desktop under the process and fail its USER32 initialization
    /// (`0xC0000142`), as the restricted helper tests showed.
    desktop: Option<super::station::SandboxDesktop>,
}

impl Process {
    fn job_handle(&self) -> HANDLE {
        self.job.as_raw_handle()
    }

    fn process_handle(&self) -> HANDLE {
        self.child.as_raw_handle()
    }

    /// Assigns the suspended process to its job, checks it is in it, reads its identity
    /// and only then resumes it.
    fn contain(&self) -> Result<ProcessIdentity, ProcessError> {
        let (job, process) = (self.job_handle(), self.process_handle());
        // SAFETY: both handles are open; the process handle has full access.
        if unsafe { AssignProcessToJobObject(job, process) } == 0 {
            return Err(spawn_error(HostCall::AssignToJob));
        }
        let mut in_job = 0;
        // SAFETY: both handles are open and `in_job` is a live BOOL.
        if unsafe { IsProcessInJob(process, job, &mut in_job) } == 0 {
            return Err(spawn_error(HostCall::CheckJob));
        }
        if in_job == 0 {
            return Err(ProcessError::NotInJob);
        }
        let start_time_ticks =
            creation_ticks(process).ok_or_else(|| spawn_error(HostCall::ReadProcessTimes))?;
        let identity = ProcessIdentity {
            pid: self.child.id(),
            start_time_ticks,
        };
        resume_threads(identity.pid)?;
        Ok(identity)
    }

    /// Kills a process whose start failed, through its job and directly, and waits a
    /// bounded time; dropping the value then closes the job.
    fn discard(self) {
        // SAFETY: both handles are open. A failure leaves the job's kill-on-close, which
        // runs when the job handle closes below.
        unsafe {
            TerminateJobObject(self.job_handle(), KILLED_EXIT_CODE);
            TerminateProcess(self.process_handle(), KILLED_EXIT_CODE);
            WaitForSingleObject(self.process_handle(), DISCARD_WAIT_MS);
        }
    }

    /// Observes, within `within`, the process handle signalled, its exit code and no
    /// active process left in its job.
    pub(super) fn observe(&self, within: Duration) -> Result<Ended, NoProof> {
        observe_end(self.process_handle(), self.job_handle(), within)
    }

    /// Reads the job's information `T` under its class; `None` when the call failed, its
    /// error left for the caller to read before any other Windows call.
    fn query_job<T: JobInformation>(&self) -> Option<T> {
        query_job_handle(self.job_handle())
    }

    /// Kills every process in the job with `code`.
    pub(super) fn kill(&self, code: u32) -> Result<(), NoProof> {
        kill_job(self.job_handle(), code)
    }

    /// Duplicates the job (terminate and query) and the process (synchronize and limited
    /// query) into `holder`'s process; nothing is left there when the second fails.
    pub(super) fn share_with(&self, holder: &Process) -> Result<SharedHandles, ProcessError> {
        let target = holder.process_handle();
        let job = duplicate_into(
            self.job_handle(),
            target,
            JOB_OBJECT_TERMINATE | JOB_OBJECT_QUERY,
        )?;
        match duplicate_into(
            self.process_handle(),
            target,
            PROCESS_SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION,
        ) {
            Ok(process) => Ok(SharedHandles { job, process }),
            Err(error) => {
                close_in(target, job);
                Err(error)
            }
        }
    }

    /// [`Process::share_with`] into this process itself (tests).
    #[cfg(test)]
    pub(super) fn share_with_current(&self) -> Result<SharedHandles, ProcessError> {
        // SAFETY: GetCurrentProcess takes nothing and returns this process's pseudo-handle.
        let current = unsafe { GetCurrentProcess() };
        let job = duplicate_into(self.job_handle(), current, JOB_OBJECT_TERMINATE | JOB_OBJECT_QUERY)?;
        let process = duplicate_into(
            self.process_handle(),
            current,
            PROCESS_SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION,
        )?;
        Ok(SharedHandles { job, process })
    }

    /// Duplicates the process's own job (query access) into the process itself.
    pub(super) fn share_own_job(&self) -> Result<u64, ProcessError> {
        duplicate_into(self.job_handle(), self.process_handle(), JOB_OBJECT_QUERY)
    }

    /// Closes `handle` in the process; best effort.
    pub(super) fn close_in_process(&self, handle: u64) {
        close_in(self.process_handle(), handle);
    }

    /// What the job has used so far: its basic accounting and the peak commit of its
    /// extended limit information, each read once through the job handle. A count no job
    /// can have, a negative CPU time or one past `u64::MAX`, is refused as invalid data
    /// rather than read low.
    pub(super) fn usage(&self) -> Result<JobUsage, ProcessError> {
        let counts: JOBOBJECT_BASIC_ACCOUNTING_INFORMATION = self
            .query_job()
            .ok_or_else(|| spawn_error(HostCall::ReadJobUsage))?;
        let limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = self
            .query_job()
            .ok_or_else(|| spawn_error(HostCall::ReadJobUsage))?;
        let invalid = || ProcessError::HostCall {
            call: HostCall::ReadJobUsage,
            os_error: ERROR_INVALID_DATA,
        };
        let user = u64::try_from(counts.TotalUserTime).map_err(|_| invalid())?;
        let kernel = u64::try_from(counts.TotalKernelTime).map_err(|_| invalid())?;
        Ok(JobUsage {
            cpu_time_ticks: user.checked_add(kernel).ok_or_else(invalid)?,
            active_processes: counts.ActiveProcesses,
            total_processes: counts.TotalProcesses,
            peak_committed_bytes: u64::try_from(limits.PeakJobMemoryUsed).map_err(|_| invalid())?,
        })
    }
}

/// Contains a suspended process in its job and resumes it; one that cannot be contained
/// is killed before it runs. Both starts, ordinary and confined, end here.
fn start_contained(process: Process) -> Result<(Process, ProcessIdentity), ProcessError> {
    match process.contain() {
        Ok(identity) => Ok((process, identity)),
        Err(error) => {
            process.discard();
            Err(error)
        }
    }
}

/// Starts `command` suspended under `confinement` (see [`Confinement`]), contains it in a
/// new job and resumes it, through the same steps as [`spawn`].
pub(super) fn spawn_confined(
    command: &Command,
    confinement: &Confinement,
) -> Result<(Process, ProcessIdentity), ProcessError> {
    let job = create_job()?;
    let (handle, pid) = create_suspended(command, confinement)?;
    start_contained(Process {
        job,
        child: Held::Confined { handle, pid },
        desktop: None,
    })
}

/// A new job with kill-on-close, no breakaway, and `start`'s active-process and memory
/// limits, die-on-unhandled-exception and UI restrictions.
fn create_limited_job(start: &RestrictedStart) -> Result<OwnedHandle, ProcessError> {
    // SAFETY: both pointers may be null: default security, no name.
    let job = owned(unsafe { CreateJobObjectW(null(), null()) })
        .ok_or_else(|| spawn_error(HostCall::CreateJob))?;
    let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
    limits.BasicLimitInformation.LimitFlags = start.job.limit_flags();
    limits.BasicLimitInformation.ActiveProcessLimit = start.job.active_process_limit;
    limits.JobMemoryLimit = usize::try_from(start.job.job_memory_limit_bytes)
        .map_err(|_| spawn_error(HostCall::LimitJob))?;
    let ui = JOBOBJECT_BASIC_UI_RESTRICTIONS {
        UIRestrictionsClass: start.job.ui_class(),
    };
    // SAFETY: the job handle is open and each structure is live and of the stated size.
    let set = unsafe {
        SetInformationJobObject(
            job.as_raw_handle(),
            JobObjectExtendedLimitInformation,
            (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
            size_u32::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>(),
        ) != 0
            && SetInformationJobObject(
                job.as_raw_handle(),
                JobObjectBasicUIRestrictions,
                (&ui as *const JOBOBJECT_BASIC_UI_RESTRICTIONS).cast(),
                size_u32::<JOBOBJECT_BASIC_UI_RESTRICTIONS>(),
            ) != 0
    };
    if !set {
        return Err(spawn_error(HostCall::LimitJob));
    }
    Ok(job)
}

/// Starts `command` suspended under `start` (see
/// [`RestrictedStart`](super::RestrictedStart)), notes its handle count while it is
/// suspended, contains it in a new job with `start`'s limits and resumes it, through the
/// same steps as [`spawn`].
pub(super) fn spawn_restricted(
    command: &Command,
    mut start: RestrictedStart,
) -> Result<(Process, ProcessIdentity, StartObservation), ProcessError> {
    let job = create_limited_job(&start)?;
    let created = create_restricted_suspended(command, &mut start)?;
    let observation = created.observation;
    let (process, identity) = start_contained(Process {
        job,
        child: Held::Confined {
            handle: created.handle,
            pid: created.pid,
        },
        // The desktop outlives the start: see `Process::desktop`.
        desktop: Some(start.desktop),
    })?;
    Ok((process, identity, observation))
}

impl Process {
    /// The restrictions of the held process and its job, read back through the handles
    /// held since its creation.
    pub(super) fn read_restrictions(&self) -> Result<RestrictionReadback, ReadbackError> {
        read_back(self.process_handle(), self.job_handle())
    }
}

/// How the host holds a process it started: as the child `Command` started, or by the
/// handle and PID a confined start returned.
enum Held {
    Started(Child),
    Confined { handle: OwnedHandle, pid: u32 },
}

impl Held {
    fn id(&self) -> u32 {
        match self {
            Self::Started(child) => child.id(),
            Self::Confined { pid, .. } => *pid,
        }
    }
}

impl AsRawHandle for Held {
    fn as_raw_handle(&self) -> RawHandle {
        match self {
            Self::Started(child) => child.as_raw_handle(),
            Self::Confined { handle, .. } => handle.as_raw_handle(),
        }
    }
}
