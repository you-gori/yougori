//! What a host process's job has used, as the host's own job accounting counts it (VM part
//! §8.2 "Detection and audit"; VM-W43 over VM-W42; M17C).
//!
//! A [`HostProcess`](super::HostProcess) runs in a job of its own that holds every process
//! it starts, so the job's accounting counts the process and all its descendants. The host
//! reads it through the job handle it holds; nothing the process or its guest writes
//! changes it. On Windows the counts come from `QueryInformationJobObject`: the basic
//! accounting (`JobObjectBasicAccountingInformation`) gives the CPU time and the process
//! counts, and the extended limit information (`JobObjectExtendedLimitInformation`) gives
//! the job's peak committed memory.
//!
//! The job's current committed memory is not read. Windows reports it only through the
//! undocumented `JobObjectMemoryUsageInformation` class, which windows-sys 0.61 does not
//! expose; the documented interfaces give the peak alone. The peak never reads low, and it
//! never falls while the job lives.

use serde::Serialize;

/// What a host process's job has used so far, read once through the job handle the host
/// holds. Never read back.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct JobUsage {
    /// The CPU time every process the job has held spent, user plus kernel, ended
    /// processes included, in 100-nanosecond ticks. It never decreases.
    pub cpu_time_ticks: u64,
    /// The processes in the job now.
    pub active_processes: u32,
    /// The processes the job has held over its life, ended ones included.
    pub total_processes: u32,
    /// The most memory the job's processes had committed together at any one time, in
    /// bytes. A peak, not the current commit: see the module notes.
    pub peak_committed_bytes: u64,
}

impl JobUsage {
    /// The length of one tick of [`JobUsage::cpu_time_ticks`], in nanoseconds.
    pub const NANOS_PER_TICK: u64 = 100;
}
