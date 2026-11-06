//! The common process clock includes host suspend, without consulting civil time.
//! Lease expiry must not pause when a laptop sleeps (VM-CP-18 / CORE-04).
//!
//! Windows: QueryInterruptTimePrecise; Linux: CLOCK_BOOTTIME; macOS:
//! mach_continuous_time. A native read/conversion failure stops this process,
//! rather than returning a fabricated timestamp or silently changing clocks.
//! A sentinel would be unsafe: a new lease could start at that same sentinel and
//! never see elapsed time. Process-death recovery is the existing cleanup path.

/// Boot-relative elapsed nanoseconds, comparable only between processes on this
/// host in this boot. Never serialize this as a remote or persisted authority.
pub(crate) fn nanos() -> u64 {
    match native_nanos() {
        Some(nanos) => nanos,
        None => {
            eprintln!("The host elapsed clock is unavailable; the process cannot enforce time-bounded authority.");
            std::process::abort()
        }
    }
}

#[cfg(windows)]
fn native_nanos() -> Option<u64> {
    let mut ticks = 0;
    // SAFETY: a valid output pointer; this API has no failure return. The count
    // includes sleep/hibernation and is independent of wall-clock adjustments.
    unsafe {
        windows_sys::Win32::System::WindowsProgramming::QueryInterruptTimePrecise(&mut ticks);
    }
    ticks.checked_mul(100)
}

#[cfg(target_os = "linux")]
fn native_nanos() -> Option<u64> {
    let mut time = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: CLOCK_BOOTTIME is a supported Linux clock and time is writable.
    if unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut time) } != 0 {
        return None;
    }
    let seconds = u64::try_from(time.tv_sec).ok()?;
    let fraction = u64::try_from(time.tv_nsec)
        .ok()
        .filter(|n| *n < 1_000_000_000)?;
    seconds.checked_mul(1_000_000_000)?.checked_add(fraction)
}

#[cfg(target_os = "macos")]
fn native_nanos() -> Option<u64> {
    use std::sync::OnceLock;
    static RATIO: OnceLock<Option<(u32, u32)>> = OnceLock::new();
    extern "C" {
        fn mach_continuous_time() -> u64;
    }
    let (numer, denom) = (*RATIO.get_or_init(|| {
        let mut info = libc::mach_timebase_info { numer: 0, denom: 0 };
        // SAFETY: a valid output structure, cached after its first read.
        (unsafe { libc::mach_timebase_info(&mut info) } == libc::KERN_SUCCESS
            && info.numer != 0
            && info.denom != 0)
            .then_some((info.numer, info.denom))
    }))?;
    // SAFETY: available on the application's minimum macOS version; no pointers.
    let ticks = unsafe { mach_continuous_time() };
    u64::try_from(u128::from(ticks) * u128::from(numer) / u128::from(denom)).ok()
}

#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
fn native_nanos() -> Option<u64> {
    // There is no validated suspend-aware clock on another platform.
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(any(windows, target_os = "linux", target_os = "macos"))]
    fn the_native_clock_advances_without_wall_clock_input() {
        let before = native_nanos().expect("native elapsed clock");
        std::thread::sleep(std::time::Duration::from_millis(5));
        assert!(native_nanos().unwrap() > before);
    }
}
