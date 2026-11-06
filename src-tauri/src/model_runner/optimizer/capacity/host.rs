//! Host RAM and CPU-initialization capacity on the existing ledger (S03, INT-01).
//! This is not a vCPU allocator. Windows uses OS-reusable physical RAM, capped by
//! commit headroom; clean standby pages are immediately reclaimable, not pinned use.
//! Managed resident RAM still stays in observed usage without trustworthy attribution;
//! reservations do not pretend to prove residency. Linux retains its MemFree probe.
use super::*;
use crate::foundation::ids::MonotonicTime;
use crate::foundation::ledger::HostResource;

const RAM: ResourceKey = ResourceKey::Host(HostResource::Ram);
const CPU_INIT: ResourceKey = ResourceKey::Host(HostResource::CpuInitializationSlots);
const GIB: u64 = 1 << 30;

#[derive(Clone, Debug)]
struct HostSnapshot {
    host: HostSubject,
    total: u64,
    free: u64,
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
    for (key, total, reserved, used) in [
        (RAM, snapshot.total, reserve, snapshot.total - snapshot.free),
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
    let (total, free) = memory(shutdown).await?;
    let initialization_slots = std::thread::available_parallelism()
        .map_err(|_| "Host CPU initialization capacity is unavailable.")?
        .get() as u64;
    let snapshot = HostSnapshot {
        host,
        total,
        free,
        initialization_slots,
        observed_at,
    };
    snapshot.validate()?;
    Ok(snapshot)
}

#[cfg(windows)]
async fn memory(shutdown: &CancellationToken) -> Result<(u64, u64), String> {
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
    windows_memory(status.ullTotalPhys, status.ullAvailPhys, status.ullAvailPageFile)
}

#[cfg(target_os = "linux")]
async fn memory(shutdown: &CancellationToken) -> Result<(u64, u64), String> {
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
        parse_meminfo(std::str::from_utf8(&bytes).map_err(|_| "Host RAM probe is not UTF-8.")?)
    };
    tokio::select! {
        biased;
        _ = shutdown.cancelled() => Err("Host capacity probe cancelled.".into()),
        result = tokio::time::timeout(Duration::from_secs(2), read) =>
            result.unwrap_or_else(|_| Err("Host RAM probe timed out.".into())),
    }
}

#[cfg(not(any(windows, target_os = "linux")))]
async fn memory(_: &CancellationToken) -> Result<(u64, u64), String> {
    Err("Host RAM admission has no reviewed probe for this platform.".into())
}

#[cfg(any(windows, test))]
fn windows_memory(total: u64, available: u64, commit_available: u64) -> Result<(u64, u64), String> {
    if total == 0 || total > 1 << 60 || available > total {
        return Err("Host RAM probe is inconsistent.".into());
    }
    Ok((total, available.min(commit_available)))
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
