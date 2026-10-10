//! Guests must never outlive the application, even when it is killed.
//!
//! Every QEMU child is placed in one process-wide job object with
//! `KILL_ON_JOB_CLOSE`. A normal exit still shuts guests down gracefully first;
//! this is the failsafe for a crash, a forced quit, or a debugger stop, where
//! an abandoned VM would otherwise keep holding its disk.

#[cfg(windows)]
pub fn contain(child: &tokio::process::Child) -> Result<(), String> {
    use std::sync::OnceLock;
    use windows_sys::Win32::System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
        SetInformationJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    };
    static JOB: OnceLock<usize> = OnceLock::new();
    let handle = child.raw_handle().ok_or("Guest process handle is unavailable")?;
    // The handle is deliberately never closed: the job lives as long as this
    // process, and closing it would terminate every guest immediately.
    let job = *JOB.get_or_init(|| unsafe {
        let job = CreateJobObjectW(std::ptr::null(), std::ptr::null());
        if job.is_null() {
            return 0;
        }
        let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        if SetInformationJobObject(
            job,
            JobObjectExtendedLimitInformation,
            (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
            std::mem::size_of_val(&limits) as u32,
        ) == 0
        {
            windows_sys::Win32::Foundation::CloseHandle(job);
            return 0;
        }
        job as usize
    });
    if job == 0 {
        return Err("Guest job containment is unavailable; refusing an uncontained runtime".into());
    }
    if unsafe { AssignProcessToJobObject(job as _, handle as _) } == 0 {
        return Err(format!("Could not contain guest process: {}", std::io::Error::last_os_error()));
    }
    Ok(())
}

#[cfg(not(windows))]
pub fn contain(_child: &tokio::process::Child) -> Result<(), String> { Ok(()) }
