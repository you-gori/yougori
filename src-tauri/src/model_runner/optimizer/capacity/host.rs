//! Host RAM and CPU-initialization capacity on the existing ledger (S03, INT-01).
//! This is not a vCPU allocator. Windows uses OS-reusable physical RAM, capped by
//! commit headroom; clean standby pages are immediately reclaimable, not pinned use.
//! Managed resident RAM still stays in observed usage without trustworthy attribution;
//! reservations do not pretend to prove residency. Linux retains its MemFree probe.
use super::*;
use crate::foundation::ids::MonotonicTime;
use crate::foundation::ledger::{HostResource, ReservationState};

const RAM: ResourceKey = ResourceKey::Host(HostResource::Ram);
const CPU_INIT: ResourceKey = ResourceKey::Host(HostResource::CpuInitializationSlots);
const GIB: u64 = 1 << 30;

#[derive(Clone, Debug)]
struct HostSnapshot {
    host: HostSubject,
    total: u64,
    free: u64,
    /// `free` is the commit Windows has left (a page file of fixed size), not physical memory: a
    /// running VM's whole guest memory is used in it from QEMU's start ([`running_vms`]).
    commit_bound: bool,
    initialization_slots: u64,
    observed_at: MonotonicTime,
}

impl HostSnapshot {
    fn validate(&self) -> Result<(), String> {
        if self.total == 0
            || self.total > 1 << 60
            || self.free > self.total
            || self.initialization_slots == 0
            || self.initialization_slots > 1 << 20
        {
            return Err("Host capacity evidence is missing or inconsistent.".into());
        }
        Ok(())
    }
}

/// Updates the same owner regardless of which consumer arrived first. No tenant
/// budget is invented: the VM supervisor must install its reviewed budget before
/// reserving. Existing budgets, reservations, GPU binding and history stay intact.
fn publish<C: Clock>(
    owner: &Mutex<Option<Accounting<C>>>,
    create: impl FnOnce(HostSubject) -> Accounting<C>,
    snapshot: &HostSnapshot,
) -> Result<SharedLedger<C>, String> {
    snapshot.validate()?;
    let mut owner = owner
        .lock()
        .map_err(|_| "Host accounting requires engine recovery.")?;
    if owner.is_none() {
        let account = create(snapshot.host);
        update(&account, snapshot)?;
        *owner = Some(account);
    } else {
        update(owner.as_ref().unwrap(), snapshot)?;
    }
    let account = owner.as_ref().unwrap();
    let shared = account.ledger.clone();
    let export = account.export.clone();
    drop(owner);
    // Same history owner/export as GPU admission, never filesystem I/O under a
    // capacity lock. A host with no model must not lose its VM history.
    ledger_history::export_in_background(export);
    Ok(shared)
}

/// The host memory of the VMs running now under their own reservations, which a commit-bound
/// Windows reading already counts as used: QEMU commits a VM's whole guest memory when it starts
/// (its job memory limit is the reservation), so without this each running VM counted twice, once
/// in the observed use and again as its reservation, and a second harness VM was refused on a
/// computer with room for it. A physical reading (a page file Windows sizes, or Linux's MemFree)
/// holds only the pages a guest touched, so every reservation stays charged in full and only those
/// pages count twice, which errs on the side of room ([`update`]). HCS GPU VMs commit lazily (they
/// hold VRAM too) and stay in the observed use.
fn running_vms<C: Clock>(ledger: &Ledger<C>) -> u64 {
    if !cfg!(windows) {
        return 0;
    }
    ledger
        .open_reservations()
        .filter(|r| {
            r.parent().is_none()
                && r.provenance().purpose == CostPurpose::VmResources
                && matches!(r.state(), ReservationState::InUse | ReservationState::Releasing)
                && !r.current().iter().any(|(key, amount)| matches!(key, ResourceKey::Vram(_)) && amount > 0)
        })
        .map(|r| r.current().get(RAM))
        .sum()
}

fn update<C: Clock>(account: &Accounting<C>, snapshot: &HostSnapshot) -> Result<(), String> {
    let mut ledger = account
        .ledger
        .lock()
        .map_err(|_| "Host accounting requires engine recovery.")?;
    if ledger.host() != snapshot.host {
        return Err(
            "Host capacity identity changed. Restart the engine after checking the host.".into(),
        );
    }
    // Same default headroom as the existing host scheduler: 10%, at least 1 GiB.
    // This reserve is never available to a managed workload.
    let reserve = (snapshot.total / 10).max(GIB).min(snapshot.total);
    // Subtracting a VM's whole reservation from a physical reading, which holds only the pages its
    // guest touched, offered the rest of that reservation to other VMs and models again.
    let vms = if snapshot.commit_bound { running_vms(&ledger) } else { 0 };
    let observed = (snapshot.total - snapshot.free).saturating_sub(vms);
    for (key, total, reserved, used) in [
        (RAM, snapshot.total, reserve, observed),
        // These are this engine's initialization slots, bounded by OS parallelism,
        // not a statement that external CPU use is zero or that a VM owns vCPUs.
        (CPU_INIT, snapshot.initialization_slots, 0, 0),
    ] {
        ledger
            .declare_capacity_observed_at(
                key,
                CapacityDeclaration {
                    total,
                    supervisor_reserve: reserved,
                    unmanaged_in_use: used,
                    source: SourceClass::HostProbe,
                },
                snapshot.observed_at,
            )
            .map_err(|e| e.to_string())?;
    }
    let mut history = account
        .history
        .lock()
        .map_err(|_| "Host accounting requires engine recovery.")?;
    history.collect(&mut *ledger);
    account.export.stage(&mut history);
    Ok(())
}

/// Refresh before a new host-level reservation. Errors are a refusal, never an
/// implicit capacity fallback. The synchronous accessor may return a ledger with
/// expired observations; its own admission checks reject those observations.
pub(crate) async fn refresh(
    shutdown: &CancellationToken,
) -> Result<SharedLedger<SystemClock>, String> {
    let snapshot = observe(shutdown).await?;
    if shutdown.is_cancelled() {
        return Err("Host capacity probe cancelled.".into());
    }
    publish(
        &HOST,
        |host| Accounting::for_host(*HOST_CLOCK, host).exporting_to(ledger_history::engine()),
        &snapshot,
    )
}

async fn observe(shutdown: &CancellationToken) -> Result<HostSnapshot, String> {
    // Take this before I/O, using the very same clock that constructs the ledger.
    let observed_at = HOST_CLOCK.now();
    if shutdown.is_cancelled() {
        return Err("Host capacity probe cancelled.".into());
    }
    let machine = probe::machine(shutdown).await?;
    let host = probe::identity(&machine)?;
    let (total, free, commit_bound) = memory(shutdown).await?;
    let initialization_slots = std::thread::available_parallelism()
        .map_err(|_| "Host CPU initialization capacity is unavailable.")?
        .get() as u64;
    let snapshot = HostSnapshot {
        host,
        total,
        free,
        commit_bound,
        initialization_slots,
        observed_at,
    };
    snapshot.validate()?;
    Ok(snapshot)
}

/// The host's memory in bytes, what of it is free for a new reservation, and whether that free
/// amount is the commit Windows has left rather than physical memory.
#[cfg(windows)]
async fn memory(shutdown: &CancellationToken) -> Result<(u64, u64, bool), String> {
    use windows_sys::Win32::System::SystemInformation::{GlobalMemoryStatusEx, MEMORYSTATUSEX};
    if shutdown.is_cancelled() { return Err("Host RAM probe cancelled.".into()); }
    let mut status = MEMORYSTATUSEX {
        dwLength: std::mem::size_of::<MEMORYSTATUSEX>() as u32,
        ..Default::default()
    };
    // SAFETY: the initialized, writable structure has the API's required size.
    if unsafe { GlobalMemoryStatusEx(&mut status) } == 0 {
        return Err(format!("Host RAM probe failed: {}", std::io::Error::last_os_error()));
    }
    // ullAvailPhys includes standby pages that need no disk write before reuse.
    // ullAvailPageFile bounds this process's remaining commit, including Job limits.
    // https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/ns-sysinfoapi-memorystatusex
    // When Windows sizes the page file itself, commit grows on demand and is no hard limit:
    // WSL 2's VM keeps tens of GB committed that it does not use (the models' VM on a 64 GB laptop
    // held 30 GB with 8 GB resident), and counting that commit refused every VM there. Physical
    // memory decides then; a fixed page file keeps its commit limit.
    let commit = if page_file_managed() { status.ullAvailPhys } else { status.ullAvailPageFile };
    windows_memory(status.ullTotalPhys, status.ullAvailPhys, commit)
}

/// Whether Windows manages the page file's size (`PagingFiles` under Memory Management).
#[cfg(windows)]
fn page_file_managed() -> bool {
    use std::os::windows::ffi::OsStrExt;
    #[link(name = "advapi32")]
    unsafe extern "system" {
        fn RegGetValueW(key: *mut std::ffi::c_void, subkey: *const u16, value: *const u16, flags: u32, kind: *mut u32, data: *mut std::ffi::c_void, size: *mut u32) -> i32;
    }
    let wide = |text: &str| std::ffi::OsStr::new(text).encode_wide().chain(Some(0)).collect::<Vec<_>>();
    let subkey = wide("SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management");
    let name = wide("PagingFiles");
    let mut buffer = vec![0u16; 4096];
    let mut size = (buffer.len() * 2) as u32;
    // HKEY_LOCAL_MACHINE, RRF_RT_REG_MULTI_SZ. Any failure keeps the commit limit.
    // SAFETY: the buffer and its size in bytes match; the names are NUL-terminated UTF-16.
    let result = unsafe {
        RegGetValueW(0x80000002u32 as i32 as isize as *mut std::ffi::c_void, subkey.as_ptr(), name.as_ptr(), 0x20, std::ptr::null_mut(), buffer.as_mut_ptr().cast(), &mut size)
    };
    result == 0 && managed_page_file(&String::from_utf16_lossy(&buffer[..(size as usize / 2).min(buffer.len())]))
}

/// `PagingFiles` entries ("C:\pagefile.sys 4096 8192", NUL-separated): Windows manages the size
/// for "?:\pagefile.sys" (every drive) or a file whose initial and maximum sizes are both 0.
#[cfg(any(windows, test))]
fn managed_page_file(entries: &str) -> bool {
    entries.split('\0').map(str::trim).filter(|entry| !entry.is_empty()).any(|entry| {
        let parts = entry.split_whitespace().collect::<Vec<_>>();
        entry.starts_with("?:") || parts.len() == 3 && parts[1] == "0" && parts[2] == "0"
    })
}

#[cfg(target_os = "linux")]
async fn memory(shutdown: &CancellationToken) -> Result<(u64, u64, bool), String> {
    use tokio::io::AsyncReadExt;
    let read = async {
        let file = tokio::fs::File::open("/proc/meminfo")
            .await
            .map_err(|_| "Host RAM probe is unavailable.")?;
        let mut bytes = Vec::new();
        file.take(65537)
            .read_to_end(&mut bytes)
            .await
            .map_err(|_| "Host RAM probe read failed.")?;
        if bytes.len() > 65536 {
            return Err("Host RAM probe exceeded its bound.".into());
        }
        // MemFree counts physical pages: a guest's untouched memory is free in it.
        parse_meminfo(std::str::from_utf8(&bytes).map_err(|_| "Host RAM probe is not UTF-8.")?)
            .map(|(total, free)| (total, free, false))
    };
    tokio::select! {
        biased;
        _ = shutdown.cancelled() => Err("Host capacity probe cancelled.".into()),
        result = tokio::time::timeout(Duration::from_secs(2), read) =>
            result.unwrap_or_else(|_| Err("Host RAM probe timed out.".into())),
    }
}

#[cfg(not(any(windows, target_os = "linux")))]
async fn memory(_: &CancellationToken) -> Result<(u64, u64, bool), String> {
    Err("Host RAM admission has no reviewed probe for this platform.".into())
}

/// The total, the free memory (physical, capped by the commit left) and whether the commit left
/// is what decided it. With a page file Windows sizes, `commit_available` is the physical memory.
#[cfg(any(windows, test))]
fn windows_memory(total: u64, available: u64, commit_available: u64) -> Result<(u64, u64, bool), String> {
    if total == 0 || total > 1 << 60 || available > total {
        return Err("Host RAM probe is inconsistent.".into());
    }
    Ok((total, available.min(commit_available), commit_available < available))
}

#[cfg(any(target_os = "linux", test))]
fn parse_meminfo(text: &str) -> Result<(u64, u64), String> {
    let mut total = None;
    let mut free = None;
    for line in text.lines() {
        let fields: Vec<_> = line.split_whitespace().collect();
        let target = match fields.first().copied() {
            Some("MemTotal:") => &mut total,
            Some("MemFree:") => &mut free,
            _ => continue,
        };
        if target.is_some() || fields.len() != 3 || fields[2] != "kB" {
            return Err("Host RAM probe contains duplicate or invalid fields.".into());
        }
        *target = Some(
            fields[1]
                .parse::<u64>()
                .ok()
                .and_then(|n| n.checked_mul(1024))
                .ok_or("Host RAM probe amount is invalid.")?,
        );
    }
    let total = total.ok_or("Host RAM total is missing.")?;
    let free = free.ok_or("Host free RAM is missing.")?;
    if total == 0 || total > 1 << 60 || free > total {
        return Err("Host RAM probe is inconsistent.".into());
    }
    Ok((total, free))
}

#[cfg(test)]
mod tests;
