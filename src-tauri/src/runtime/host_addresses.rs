//! Error-aware inventory and invalidation of every local IPv4 address.
//! Traffic statistics APIs may omit software/VPN interfaces and hide failures.
use std::collections::HashSet;
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Arc,
};

#[derive(Default)]
pub(super) struct Changes {
    generation: AtomicU64,
    healthy: AtomicBool,
}
impl Changes {
    pub(super) fn generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }
    pub(super) fn healthy(&self) -> bool {
        self.healthy.load(Ordering::Acquire)
    }
    #[cfg(test)]
    pub(super) fn ready_for_test() -> Arc<Self> {
        let state = Arc::new(Self::default());
        state.healthy.store(true, Ordering::Release);
        state
    }
    #[cfg(test)]
    pub(super) fn invalidate_for_test(&self) {
        self.generation.fetch_add(1, Ordering::AcqRel);
    }
}

pub(super) fn ipv4_addresses() -> Result<HashSet<[u8; 4]>, String> {
    let addresses = native_addresses()?;
    if addresses.is_empty() {
        return Err("Host IPv4 inventory is empty; network access remains blocked".into());
    }
    Ok(addresses)
}

#[cfg(windows)]
fn native_addresses() -> Result<HashSet<[u8; 4]>, String> {
    use windows_sys::Win32::{
        NetworkManagement::IpHelper::{
            FreeMibTable, GetUnicastIpAddressTable, MIB_UNICASTIPADDRESS_TABLE,
        },
        Networking::WinSock::AF_INET,
    };
    struct Table(*mut MIB_UNICASTIPADDRESS_TABLE);
    impl Drop for Table {
        fn drop(&mut self) {
            unsafe {
                FreeMibTable(self.0.cast());
            }
        }
    }
    let mut table = std::ptr::null_mut();
    // The API owns/aligned-allocates this complete table. FreeMibTable is the
    // matching release function; no hardware, MAC or link-speed filtering.
    let status = unsafe { GetUnicastIpAddressTable(AF_INET, &mut table) };
    if status != 0 {
        return Err(format!(
            "Host IPv4 inventory: {}",
            std::io::Error::from_raw_os_error(status as i32)
        ));
    }
    if table.is_null() {
        return Err("Host IPv4 inventory returned no table".into());
    }
    let table = Table(table);
    let count = unsafe { (*table.0).NumEntries } as usize;
    if count > 65536 {
        return Err("Host IPv4 inventory exceeds its limit".into());
    }
    let rows = unsafe { std::slice::from_raw_parts((*table.0).Table.as_ptr(), count) };
    let mut result = HashSet::new();
    for row in rows {
        if unsafe { row.Address.si_family } == AF_INET {
            result.insert(unsafe { row.Address.Ipv4.sin_addr.S_un.S_addr }.to_ne_bytes());
        }
    }
    Ok(result)
}

#[cfg(unix)]
fn native_addresses() -> Result<HashSet<[u8; 4]>, String> {
    struct Addresses(*mut libc::ifaddrs);
    impl Drop for Addresses {
        fn drop(&mut self) {
            unsafe {
                libc::freeifaddrs(self.0);
            }
        }
    }
    let mut addresses = std::ptr::null_mut();
    // getifaddrs returns every address, including loopback and tunnel interfaces.
    if unsafe { libc::getifaddrs(&mut addresses) } != 0 {
        return Err(format!(
            "Host IPv4 inventory: {}",
            std::io::Error::last_os_error()
        ));
    }
    if addresses.is_null() {
        return Err("Host IPv4 inventory returned no interfaces".into());
    }
    let addresses = Addresses(addresses);
    let mut cursor = addresses.0;
    let mut result = HashSet::new();
    let mut count = 0;
    while !cursor.is_null() {
        count += 1;
        if count > 65536 {
            return Err("Host IPv4 inventory exceeds its limit".into());
        }
        let row = unsafe { &*cursor };
        if !row.ifa_addr.is_null() && unsafe { (*row.ifa_addr).sa_family } as i32 == libc::AF_INET {
            result.insert(
                unsafe {
                    (*(row.ifa_addr.cast::<libc::sockaddr_in>()))
                        .sin_addr
                        .s_addr
                }
                .to_ne_bytes(),
            );
        }
        cursor = row.ifa_next;
    }
    Ok(result)
}

#[cfg(not(any(windows, unix)))]
fn native_addresses() -> Result<HashSet<[u8; 4]>, String> {
    Err("Host IPv4 inventory is unsupported".into())
}

pub(super) struct Monitor {
    state: Arc<Changes>,
    #[cfg(windows)]
    handle: usize,
    #[cfg(unix)]
    stop: Arc<AtomicBool>,
    #[cfg(target_os = "linux")]
    wake: std::os::fd::OwnedFd,
    #[cfg(unix)]
    worker: Option<std::thread::JoinHandle<()>>,
}
impl Monitor {
    pub(super) fn state(&self) -> Arc<Changes> {
        self.state.clone()
    }
    #[cfg(windows)]
    pub(super) fn start() -> Result<Self, String> {
        use windows_sys::Win32::{
            NetworkManagement::IpHelper::{
                NotifyUnicastIpAddressChange, MIB_NOTIFICATION_TYPE, MIB_UNICASTIPADDRESS_ROW,
            },
            Networking::WinSock::AF_INET,
        };
        unsafe extern "system" fn changed(
            context: *const std::ffi::c_void,
            _: *const MIB_UNICASTIPADDRESS_ROW,
            _: MIB_NOTIFICATION_TYPE,
        ) {
            // Context is retained until CancelMibChangeNotify2 completes. This
            // callback takes no locks and never waits for/drop-cancels itself.
            if !context.is_null() {
                unsafe { &*context.cast::<Changes>() }
                    .generation
                    .fetch_add(1, Ordering::AcqRel);
            }
        }
        let state = Arc::new(Changes::default());
        let mut handle = std::ptr::null_mut();
        let status = unsafe {
            NotifyUnicastIpAddressChange(
                AF_INET,
                Some(changed),
                Arc::as_ptr(&state).cast(),
                false,
                &mut handle,
            )
        };
        if status != 0 || handle.is_null() {
            return Err(format!("Host IPv4 change watcher unavailable ({status})"));
        }
        state.healthy.store(true, Ordering::Release);
        Ok(Self {
            state,
            handle: handle as usize,
        })
    }
    #[cfg(target_os = "linux")]
    pub(super) fn start() -> Result<Self, String> {
        use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
        fn owned(fd: i32) -> Result<OwnedFd, String> {
            if fd < 0 {
                Err(format!(
                    "Host IPv4 change watcher: {}",
                    std::io::Error::last_os_error()
                ))
            } else {
                Ok(unsafe { OwnedFd::from_raw_fd(fd) })
            }
        }
        let route = owned(unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
                libc::NETLINK_ROUTE,
            )
        })?;
        let mut address: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        address.nl_family = libc::AF_NETLINK as u16;
        address.nl_groups = libc::RTMGRP_IPV4_IFADDR as u32;
        if unsafe {
            libc::bind(
                route.as_raw_fd(),
                (&address as *const libc::sockaddr_nl).cast(),
                std::mem::size_of_val(&address) as _,
            )
        } != 0
        {
            return Err(format!(
                "Host IPv4 change watcher: {}",
                std::io::Error::last_os_error()
            ));
        }
        let wake = owned(unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) })?;
        let wake_reader = wake.try_clone().map_err(|error| error.to_string())?;
        let stop = Arc::new(AtomicBool::new(false));
        let state = Arc::new(Changes::default());
        state.healthy.store(true, Ordering::Release);
        let thread_state = state.clone();
        let thread_stop = stop.clone();
        let worker = std::thread::Builder::new()
            .name("yougori-ipv4-watch".into())
            .spawn(move || {
                let watch = || -> std::io::Result<()> {
                    let mut descriptors = [
                        libc::pollfd {
                            fd: route.as_raw_fd(),
                            events: libc::POLLIN,
                            revents: 0,
                        },
                        libc::pollfd {
                            fd: wake_reader.as_raw_fd(),
                            events: libc::POLLIN,
                            revents: 0,
                        },
                    ];
                    let mut buffer = [0u8; 32768];
                    while !thread_stop.load(Ordering::Acquire) {
                        // The timeout is a teardown fallback if an eventfd write
                        // is interrupted; it performs no address enumeration.
                        if unsafe {
                            libc::poll(descriptors.as_mut_ptr(), descriptors.len() as _, 250)
                        } < 0
                        {
                            let error = std::io::Error::last_os_error();
                            if error.kind() == std::io::ErrorKind::Interrupted {
                                continue;
                            }
                            return Err(error);
                        }
                        if thread_stop.load(Ordering::Acquire) {
                            break;
                        }
                        if descriptors[0].revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL)
                            != 0
                        {
                            return Err(std::io::Error::other(
                                "Host IPv4 notification stream failed",
                            ));
                        }
                        if descriptors[0].revents & libc::POLLIN == 0 {
                            continue;
                        }
                        for _ in 0..64 {
                            if thread_stop.load(Ordering::Acquire) {
                                break;
                            }
                            let mut sender: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
                            let mut size = std::mem::size_of_val(&sender) as libc::socklen_t;
                            let received = unsafe {
                                libc::recvfrom(
                                    route.as_raw_fd(),
                                    buffer.as_mut_ptr().cast(),
                                    buffer.len(),
                                    0,
                                    (&mut sender as *mut libc::sockaddr_nl).cast(),
                                    &mut size,
                                )
                            };
                            if received < 0 {
                                let error = std::io::Error::last_os_error();
                                if error.kind() == std::io::ErrorKind::WouldBlock {
                                    break;
                                }
                                if error.kind() == std::io::ErrorKind::Interrupted {
                                    continue;
                                }
                                return Err(error);
                            }
                            if received == 0 {
                                return Err(std::io::Error::other(
                                    "Host IPv4 notification stream closed",
                                ));
                            }
                            if sender.nl_pid == 0 {
                                thread_state.generation.fetch_add(1, Ordering::AcqRel);
                            }
                        }
                    }
                    Ok(())
                };
                let _ = watch();
                thread_state.healthy.store(false, Ordering::Release);
                thread_state.generation.fetch_add(1, Ordering::AcqRel);
            })
            .map_err(|error| error.to_string())?;
        Ok(Self {
            state,
            stop,
            wake,
            worker: Some(worker),
        })
    }
    #[cfg(all(unix, not(target_os = "linux")))]
    pub(super) fn start() -> Result<Self, String> {
        // Other Unix hosts retain error-aware inventory and bounded leases.
        // This polling fallback does not claim native event notifications;
        // newly opened flows still query inventory before authorization.
        let mut previous = ipv4_addresses()?;
        let stop = Arc::new(AtomicBool::new(false));
        let state = Arc::new(Changes::default());
        state.healthy.store(true, Ordering::Release);
        let thread_state = state.clone();
        let thread_stop = stop.clone();
        let worker = std::thread::Builder::new()
            .name("yougori-ipv4-poll".into())
            .spawn(move || {
                while !thread_stop.load(Ordering::Acquire) {
                    std::thread::park_timeout(std::time::Duration::from_millis(250));
                    if thread_stop.load(Ordering::Acquire) {
                        break;
                    }
                    match ipv4_addresses() {
                        Ok(current) => {
                            if current != previous || !thread_state.healthy() {
                                thread_state.generation.fetch_add(1, Ordering::AcqRel);
                            }
                            previous = current;
                            thread_state.healthy.store(true, Ordering::Release);
                        }
                        Err(_) => {
                            thread_state.healthy.store(false, Ordering::Release);
                            thread_state.generation.fetch_add(1, Ordering::AcqRel);
                        }
                    }
                }
                thread_state.healthy.store(false, Ordering::Release);
                thread_state.generation.fetch_add(1, Ordering::AcqRel);
            })
            .map_err(|error| error.to_string())?;
        Ok(Self {
            state,
            stop,
            worker: Some(worker),
        })
    }
    #[cfg(not(any(windows, unix)))]
    pub(super) fn start() -> Result<Self, String> {
        Err("Host IPv4 change monitoring is unsupported".into())
    }
}
impl Drop for Monitor {
    fn drop(&mut self) {
        self.state.healthy.store(false, Ordering::Release);
        self.state.generation.fetch_add(1, Ordering::AcqRel);
        #[cfg(windows)]
        {
            let status = unsafe {
                windows_sys::Win32::NetworkManagement::IpHelper::CancelMibChangeNotify2(
                    self.handle as _,
                )
            };
            // Never leave the OS with a dangling callback context on a rare
            // cancellation failure. This tiny retained state is process-local.
            if status != 0 {
                std::mem::forget(self.state.clone());
            }
        }
        #[cfg(unix)]
        {
            self.stop.store(true, Ordering::Release);
            #[cfg(target_os = "linux")]
            {
                use std::os::fd::AsRawFd;
                let value = 1u64;
                unsafe {
                    libc::write(
                        self.wake.as_raw_fd(),
                        (&value as *const u64).cast(),
                        std::mem::size_of_val(&value),
                    );
                }
            }
            if let Some(worker) = self.worker.take() {
                worker.thread().unpark();
                let _ = worker.join();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn inventory_includes_software_loopback() {
        assert!(ipv4_addresses().unwrap().contains(&[127, 0, 0, 1]));
    }
    #[test]
    fn native_watch_registration_and_teardown_preserve_inventory() {
        let before = ipv4_addresses().unwrap();
        let monitor = Monitor::start().unwrap();
        let state = monitor.state();
        assert!(state.healthy());
        assert!(ipv4_addresses().unwrap().is_superset(&before));
        drop(monitor);
        assert!(!state.healthy());
    }
}
