//! M17C: CPU, memory and process-count readings from the job of a VM's host process, a
//! slice of VM-W43 over VM-W42 (docs/combined-gpu-memory-and-vm-sandbox-plan.md: the VM-W42
//! and VM-W43 rows; VM part §8.2 "Detection and audit": "label telemetry sources
//! correctly"). Tier 0 for the arithmetic, which is pure; the snapshot reads the host
//! through PX1.
//!
//! PX1 ([`HostProcess`]) starts a VM's host process, its hypervisor or VMM process
//! ([`ProcessRole::VmHost`]), in a kill-on-close job of its own that every process it starts
//! stays in, and reads the job's accounting through the job handle it holds
//! ([`HostProcess::usage`]). A [`JobSnapshot`] is one such read with the process's identity
//! and role and a reading of the shared host clock. Three V14 resources come from it, each
//! classified as the M17B adapters classify theirs ([`ResourceReading`]):
//!
//! - [`MonitoredResource::CpuMillicores`] by the [`HostObserver::HypervisorCounters`]
//!   ([`cpu_reading`]): the job's CPU time, user plus kernel, spent between two snapshots of
//!   one process, over the host clock's interval between them, in thousandths of a core,
//!   rounded down;
//! - [`MonitoredResource::MemoryBytes`] by the [`HostObserver::HypervisorCounters`]
//!   ([`memory_reading`]): the job's committed memory;
//! - [`MonitoredResource::ProcessCount`] by the [`HostObserver::Supervisor`]
//!   ([`process_count_reading`]): the processes in the job now, the host processes of the
//!   sandbox as the supervisor that holds the job counts them.
//!
//! # Why the job's counts are hypervisor counters
//!
//! They are the host's own accounting of the hypervisor process that runs the VM, kept by
//! the host kernel for the job the host created and read through the handle the host holds.
//! The guest runs inside the VM: it can make the VMM work, which is what the counts
//! measure, but it cannot write them, reset them or name another job. The counts cover
//! the VMM's own work too (device emulation, its I/O threads), which is the hypervisor
//! process's use and part of what V14 means by the counter.
//!
//! # What they miss
//!
//! Hypervisor work done outside the job is not counted: the hypervisor's own time, kernel
//! threads of the host that serve the partition, and above all a VM that the Windows Host
//! Compute Service runs in its worker process (`vmwp.exe`), which the service starts and
//! which is not in our job. Whether the job counts the VM depends on how the backend
//! launched it, so a snapshot names the hypervisor interface ([`HypervisorKind`]) and
//! [`JobCoverage`] states what follows: only a VM run inside its host process through the
//! Windows Hypervisor Platform (QEMU's WHPX accelerator) is read; an HCS-backed VM gives no
//! reading ([`JobCoverage::HcsWorkerOutsideJob`], [`Ordinary::NothingObserved`]), since the
//! job's counts would read low and low samples can clear a series that should stay
//! exceeded. Whether WHP charges the time a virtual processor spends in the guest to the
//! VMM thread that runs it depends on the hypervisor's scheduler; nothing here has measured
//! it with a running guest.
//!
//! The memory reading is the job's peak commit, not its current one. Windows reports the
//! current commit of a job only through a class windows-sys 0.61 does not expose
//! ([`JobUsage`]), so the documented peak stands in: it never reads low, but a series it
//! raised stays raised until the process ends. A VMM that commits the guest's memory when
//! it starts, as QEMU does, holds its peak from then on, so the two differ little there.
//!
//! The process count includes what Windows starts for the host process inside its job, such
//! as the console host of a console program started without a window.
//!
//! # Refusals
//!
//! The sandbox is always the execution of the process's [`ProcessRole::VmHost`], never a
//! caller's word; any other role, such as a model runner's, is refused as ordinary
//! ([`Ordinary::HostConfiguration`]). A CPU reading also refuses two snapshots of different
//! processes, boots or hypervisors, or out of time order ([`Ordinary::HostConfiguration`]);
//! closer together than [`MIN_CPU_WINDOW`] ([`Ordinary::HostConfiguration`]); or read on
//! different clock sessions ([`Ordinary::NotCurrent`]). A job that could not be read, a
//! counter that went down and an amount that does not fit are host faults
//! ([`Ordinary::HostFault`]). Without a reading, V14 reports the series' silence as
//! uncertain, never as a pass.
//!
//! Still open: the supervisor sampling these on a schedule (process wiring, S06), the
//! counters of an HCS VM (M04), packets per second, which no committed source counts
//! (M10, M02), and Unix and macOS hosts, whose cgroups and rusage are not read here.

use std::time::Duration;

use crate::foundation::evidence::{ClockSession, HypervisorKind};
use crate::foundation::ids::{Clock, MonotonicTime};
use crate::foundation::process::{
    HostProcess, JobUsage, ProcessError, ProcessIdentity, ProcessRole,
};
use crate::sandbox_contract::response::{HostObserver, MonitoredResource};

use super::observed::{Observed, Ordinary};
use super::resource::{measured, ResourceReading};

/// The observer every CPU reading names.
pub const CPU_OBSERVER: HostObserver = HostObserver::HypervisorCounters;

/// The observer every memory reading names.
pub const MEMORY_OBSERVER: HostObserver = HostObserver::HypervisorCounters;

/// The observer every process-count reading names.
pub const PROCESS_COUNT_OBSERVER: HostObserver = HostObserver::Supervisor;

/// The shortest host clock interval a CPU reading is taken over. Windows advances a job's
/// CPU times at the clock interrupt (15.6 ms by default), so a shorter interval reads
/// coarsely; V14's windows count whole seconds, so a sample a second suffices.
pub const MIN_CPU_WINDOW: Duration = Duration::from_secs(1);

/// Thousandths of a core in one core.
const MILLICORES_PER_CORE: u128 = 1_000;

/// Whether the job of a VM's host process holds the work that runs the VM, by the
/// hypervisor interface the backend launched it with.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum JobCoverage {
    /// The host process runs the VM itself through the Windows Hypervisor Platform: its
    /// threads run the virtual processors and it commits the guest's memory, so its job
    /// counts the VM.
    WholeVm,
    /// The Host Compute Service runs the VM in its worker process (`vmwp.exe`), which it
    /// starts outside our job: the job holds none of the VM's work and gives no reading.
    HcsWorkerOutsideJob,
    /// A hypervisor whose host is not a Windows job (KVM, Hypervisor.framework,
    /// Virtualization.framework): those hosts count through cgroups and rusage, not read
    /// here.
    NotJobAccounted,
}

impl JobCoverage {
    /// What a VM host process's job covers when the VM runs on `hypervisor`.
    pub const fn of(hypervisor: HypervisorKind) -> Self {
        match hypervisor {
            HypervisorKind::Whpx => Self::WholeVm,
            HypervisorKind::Hcs => Self::HcsWorkerOutsideJob,
            HypervisorKind::Kvm | HypervisorKind::Hvf | HypervisorKind::Vz => Self::NotJobAccounted,
        }
    }

    /// Why the job gives no reading of the VM, or `None` when it counts the whole VM.
    pub const fn refusal(self) -> Option<Ordinary> {
        match self {
            Self::WholeVm => None,
            Self::HcsWorkerOutsideJob => Some(Ordinary::NothingObserved),
            Self::NotJobAccounted => Some(Ordinary::HostConfiguration),
        }
    }
}

/// One read of a host process's job: what the job had used, the process it was read from
/// and what that process runs for, and the host clock reading taken right after.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JobSnapshot {
    pub(super) identity: ProcessIdentity,
    pub(super) role: ProcessRole,
    pub(super) hypervisor: HypervisorKind,
    pub(super) usage: Result<JobUsage, ProcessError>,
    pub(super) at: MonotonicTime,
    pub(super) session: ClockSession,
}

impl JobSnapshot {
    /// Reads `process`'s job, then `clock`, the shared host clock whose current session is
    /// `session`. `hypervisor` is the interface the backend launched the VM with, which
    /// decides whether the job counts the VM ([`JobCoverage`]). A job that cannot be read
    /// is kept as its error and makes no reading.
    pub fn read(
        process: &HostProcess,
        hypervisor: HypervisorKind,
        clock: &dyn Clock,
        session: ClockSession,
    ) -> Self {
        let usage = process.usage();
        Self {
            identity: process.identity(),
            role: process.role().clone(),
            hypervisor,
            usage,
            at: clock.now(),
            session,
        }
    }

    /// The process the job was read from.
    pub fn identity(&self) -> ProcessIdentity {
        self.identity
    }

    /// What the process runs for, as bound when it started.
    pub fn role(&self) -> &ProcessRole {
        &self.role
    }

    /// The hypervisor interface the VM runs on.
    pub fn hypervisor(&self) -> HypervisorKind {
        self.hypervisor
    }

    /// What the job covers of the VM.
    pub fn coverage(&self) -> JobCoverage {
        JobCoverage::of(self.hypervisor)
    }

    /// What the job had used, or why it could not be read.
    pub fn usage(&self) -> Result<&JobUsage, &ProcessError> {
        self.usage.as_ref()
    }

    /// When the job was read, on the shared host clock.
    pub fn at(&self) -> MonotonicTime {
        self.at
    }

    /// The host clock session [`JobSnapshot::at`] was read from.
    pub fn session(&self) -> ClockSession {
        self.session
    }

    /// The observation of a snapshot whose job counts a VM, about the sandbox of its
    /// [`ProcessRole::VmHost`], with what the job had used; or why there is none.
    fn of_vm(&self) -> Result<(Observed, &JobUsage), Ordinary> {
        let ProcessRole::VmHost { execution, .. } = &self.role else {
            return Err(Ordinary::HostConfiguration);
        };
        if let Some(reason) = self.coverage().refusal() {
            return Err(reason);
        }
        let usage = self.usage.as_ref().map_err(|_| Ordinary::HostFault)?;
        let observed = Observed {
            sandbox: execution.clone(),
            at: self.at,
            session: self.session,
        };
        Ok((observed, usage))
    }
}

/// The CPU reading over two snapshots of one VM host process (pure): the job's CPU time
/// spent between them over the host clock's interval, in millicores, rounded down, at
/// `later`'s time; or why there is none.
pub fn cpu_reading(earlier: &JobSnapshot, later: &JobSnapshot) -> ResourceReading {
    match cpu_millicores(earlier, later) {
        Ok((observed, millicores)) => measured(
            &observed,
            MonitoredResource::CpuMillicores,
            CPU_OBSERVER,
            millicores,
        ),
        Err(reason) => ResourceReading::Ordinary { reason },
    }
}

fn cpu_millicores(earlier: &JobSnapshot, later: &JobSnapshot) -> Result<(Observed, u64), Ordinary> {
    let (_, before) = earlier.of_vm()?;
    let (observed, after) = later.of_vm()?;
    if earlier.identity != later.identity
        || earlier.role != later.role
        || earlier.hypervisor != later.hypervisor
    {
        return Err(Ordinary::HostConfiguration);
    }
    if earlier.session != later.session {
        return Err(Ordinary::NotCurrent);
    }
    let elapsed = later
        .at
        .checked_duration_since(earlier.at)
        .ok_or(Ordinary::HostConfiguration)?;
    if elapsed < MIN_CPU_WINDOW {
        return Err(Ordinary::HostConfiguration);
    }
    // The job's accounting only grows: a counter that went down is not this job's.
    if after.total_processes < before.total_processes {
        return Err(Ordinary::HostFault);
    }
    let spent_ticks = after
        .cpu_time_ticks
        .checked_sub(before.cpu_time_ticks)
        .ok_or(Ordinary::HostFault)?;
    let millicores = u128::from(spent_ticks)
        .checked_mul(u128::from(JobUsage::NANOS_PER_TICK))
        .and_then(|nanos| nanos.checked_mul(MILLICORES_PER_CORE))
        .and_then(|scaled| scaled.checked_div(elapsed.as_nanos()))
        .and_then(|millicores| u64::try_from(millicores).ok())
        .ok_or(Ordinary::HostFault)?;
    Ok((observed, millicores))
}

/// The memory reading of one snapshot of a VM host process (pure): the job's peak
/// committed memory, in bytes, at the snapshot's time; or why there is none.
pub fn memory_reading(snapshot: &JobSnapshot) -> ResourceReading {
    match snapshot.of_vm() {
        Ok((observed, usage)) => measured(
            &observed,
            MonitoredResource::MemoryBytes,
            MEMORY_OBSERVER,
            usage.peak_committed_bytes,
        ),
        Err(reason) => ResourceReading::Ordinary { reason },
    }
}

/// The process-count reading of one snapshot of a VM host process (pure): the processes
/// in its job, at the snapshot's time; or why there is none.
pub fn process_count_reading(snapshot: &JobSnapshot) -> ResourceReading {
    match snapshot.of_vm() {
        Ok((observed, usage)) => measured(
            &observed,
            MonitoredResource::ProcessCount,
            PROCESS_COUNT_OBSERVER,
            u64::from(usage.active_processes),
        ),
        Err(reason) => ResourceReading::Ordinary { reason },
    }
}
