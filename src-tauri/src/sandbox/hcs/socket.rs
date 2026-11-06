//! Private sockets only: one filesystem socket and one exact VM/service pair.
use std::{
    io,
    net::TcpStream,
    os::windows::io::FromRawSocket,
    path::Path,
    time::{Duration, Instant},
};
use windows_sys::{core::GUID, Win32::Networking::WinSock::*};

pub struct Listener {
    socket: SOCKET,
    vm: Option<GUID>,
}
#[repr(C)]
struct HyperAddress {
    family: u16,
    reserved: u16,
    vm: GUID,
    service: GUID,
}
fn guid(id: uuid::Uuid) -> GUID {
    let (data1, data2, data3, data4) = id.as_fields();
    GUID {
        data1,
        data2,
        data3,
        data4: *data4,
    }
}
impl Listener {
    fn create(
        family: i32,
        protocol: i32,
        address: *const SOCKADDR,
        size: usize,
        vm: Option<GUID>,
    ) -> io::Result<Self> {
        unsafe {
            let mut data = std::mem::zeroed();
            if WSAStartup(0x202, &mut data) != 0 {
                return Err(io::Error::last_os_error());
            }
            let fd = WSASocketW(
                family,
                SOCK_STREAM,
                protocol,
                std::ptr::null(),
                0,
                WSA_FLAG_OVERLAPPED | WSA_FLAG_NO_HANDLE_INHERIT,
            );
            if fd == INVALID_SOCKET {
                WSACleanup();
                return Err(io::Error::from_raw_os_error(WSAGetLastError()));
            }
            let listener = Self { socket: fd, vm };
            if bind(fd, address, size as i32) != 0 || listen(fd, 1) != 0 {
                return Err(io::Error::from_raw_os_error(WSAGetLastError()));
            }
            let mut nonblock = 1;
            if ioctlsocket(fd, FIONBIO, &mut nonblock) != 0 {
                return Err(io::Error::from_raw_os_error(WSAGetLastError()));
            }
            Ok(listener)
        }
    }
    pub fn local(path: &Path) -> io::Result<Self> {
        let bytes = crate::sandbox::qemu_host::socket_path_bytes(path).map_err(io::Error::other)?;
        let mut addr: SOCKADDR_UN = unsafe { std::mem::zeroed() };
        addr.sun_family = AF_UNIX;
        for (dst, src) in addr.sun_path.iter_mut().zip(bytes.iter()) {
            *dst = *src as i8;
        }
        Self::create(
            AF_UNIX as i32,
            0,
            (&addr as *const SOCKADDR_UN).cast(),
            std::mem::size_of_val(&addr),
            None,
        )
    }
    pub fn hyper(vm: uuid::Uuid) -> io::Result<Self> {
        let vm = guid(vm);
        let addr = HyperAddress {
            family: 34,
            reserved: 0,
            vm,
            service: guid(super::api::SERVICE.parse().expect("fixed service UUID")),
        };
        Self::create(
            34,
            1,
            (&addr as *const HyperAddress).cast(),
            std::mem::size_of_val(&addr),
            Some(vm),
        )
    }
    pub fn accept(&self, within: Duration) -> io::Result<TcpStream> {
        let deadline = Instant::now() + within;
        loop {
            unsafe {
                let mut address: SOCKADDR_STORAGE = std::mem::zeroed();
                let mut length = std::mem::size_of_val(&address) as i32;
                let fd = accept(
                    self.socket,
                    (&mut address as *mut SOCKADDR_STORAGE).cast(),
                    &mut length,
                );
                if fd != INVALID_SOCKET {
                    if let Some(expected) = self.vm {
                        let actual =
                            &*((&address as *const SOCKADDR_STORAGE).cast::<HyperAddress>());
                        if length != std::mem::size_of::<HyperAddress>() as i32
                            || actual.family != 34
                            || (
                                actual.vm.data1,
                                actual.vm.data2,
                                actual.vm.data3,
                                actual.vm.data4,
                            ) != (
                                expected.data1,
                                expected.data2,
                                expected.data3,
                                expected.data4,
                            )
                        {
                            closesocket(fd);
                            return Err(io::Error::other("Hyper-V socket peer is not this VM"));
                        }
                    }
                    let mut blocking = 0;
                    if ioctlsocket(fd, FIONBIO, &mut blocking) != 0 {
                        closesocket(fd);
                        return Err(io::Error::last_os_error());
                    }
                    return Ok(TcpStream::from_raw_socket(fd as _));
                }
                let error = WSAGetLastError();
                if error != WSAEWOULDBLOCK {
                    return Err(io::Error::from_raw_os_error(error));
                }
            }
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "private VM socket did not connect",
                ));
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}
impl Drop for Listener {
    fn drop(&mut self) {
        unsafe {
            closesocket(self.socket);
            WSACleanup();
        }
    }
}
