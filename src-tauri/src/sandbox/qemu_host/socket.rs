//! An AF_UNIX stream client over Winsock, for the QEMU backend's QMP and link sockets
//! (M02, M04; docs/combined-gpu-memory-and-vm-sandbox-plan.md: VM-W16 row, line 2615;
//! VM-W19 row, line 2618; §7.3 lines 2378–2386; VM-CP-03, line 3153: QMP only on a
//! socket in the host-created private directory).
//!
//! The QEMU profile renders QMP and the guest link as QEMU AF_UNIX server sockets
//! (`-chardev socket,path=...,server=on,wait=off`) named `qmp.sock` and `link.sock` in the
//! launch's private directory. [`connect`] opens one of them as a client:
//!
//! - the path is checked first: ASCII only (Winsock's `sun_path` has no stated encoding,
//!   and QEMU reads its arguments in the ANSI code page), no NUL, and at most
//!   [`MAX_SOCKET_PATH_BYTES`], which is `SOCKADDR_UN`'s `sun_path` without its
//!   terminating NUL; a longer path is refused, never truncated;
//! - the socket is created overlapped (Winsock applies `SO_RCVTIMEO` and `SO_SNDTIMEO`
//!   only to such sockets) and not inheritable, so no child process started later
//!   receives it by accident;
//! - every receive and send is bounded by [`SocketTimeouts`]; a timeout is a typed
//!   [`SocketError::TimedOut`] inside the `io::Error`, and afterwards the stream refuses
//!   all I/O, since Winsock leaves a connection in an indeterminate state after a timed-out
//!   call;
//! - [`UnixStream::shutdown`] ends one direction or both, and
//!   [`UnixStream::peer_process_id`] asks Winsock for the process id of the peer
//!   (`SIO_AF_UNIX_GETPEERPID`), so the caller can check the socket is served by the QEMU
//!   process it started.
//!
//! The connect itself is not bounded by the timeouts: a local AF_UNIX connect completes or
//! fails at once, and a server that accepts nothing (QEMU serving another client) is
//! caught by the receive timeout while waiting for its first bytes. On Linux and other Unix
//! hosts the same client is the standard library's stream with the same timeouts (a
//! timed-out call likewise leaves it unused), its peer read through `SO_PEERCRED`; on
//! platforms with neither, [`connect`] returns [`SocketError::Unsupported`].
//!
//! The link socket is carried by the sandbox host's session pump, which reads and writes
//! it while holding the service's lock and must never block on it; a timed-out receive
//! would leave the stream unusable (above). So the pump's stream is put in non-blocking
//! mode ([`UnixStream::set_nonblocking`], `FIONBIO`): a receive with nothing to read and a
//! send the socket's buffer cannot take return `WouldBlock`, which the pump's bounded I/O
//! treats as "nothing now", and the stream stays usable. [`UnixStream`] is the
//! transport's [`StreamShutdown`] and [`PeerProcess`], and [`LinkSocketConnector`] is the
//! [`LinkConnector`] the VM service dials `link.sock` with: it connects and switches the
//! stream to non-blocking mode before a byte is read.

use std::fmt;
use std::io::{self, Read, Write};
use std::path::Path;
use std::time::Duration;

use serde::Serialize;

use crate::sandbox::link_transport::{LinkConnector, PeerProcess, StreamShutdown};
use crate::sandbox::qemu::{HostPath, MAX_WINDOWS_SOCKET_PATH_BYTES};

/// Longest socket path [`connect`] accepts, in bytes: `SOCKADDR_UN`'s 108-byte `sun_path`
/// with its terminating NUL, the bound the QEMU profile checks its private directory
/// against.
pub const MAX_SOCKET_PATH_BYTES: usize = MAX_WINDOWS_SOCKET_PATH_BYTES;
/// Shortest receive or send timeout: Winsock reads zero as "wait forever".
pub const MIN_SOCKET_TIMEOUT: Duration = Duration::from_millis(1);
/// Longest receive or send timeout.
pub const MAX_SOCKET_TIMEOUT: Duration = Duration::from_secs(300);

/// One direction of a connection, or both.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    Receive,
    Send,
    Both,
}

impl fmt::Display for Direction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Receive => "receive",
            Self::Send => "send",
            Self::Both => "both directions",
        })
    }
}

/// The host call a [`SocketError::Os`] came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SocketOperation {
    Startup,
    Create,
    SetReceiveTimeout,
    SetSendTimeout,
    SetNonBlocking,
    Connect,
    Receive,
    Send,
    Shutdown,
    PeerProcessId,
}

impl fmt::Display for SocketOperation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Startup => "starting Winsock",
            Self::Create => "creating the socket",
            Self::SetReceiveTimeout => "setting the receive timeout",
            Self::SetSendTimeout => "setting the send timeout",
            Self::SetNonBlocking => "setting the blocking mode",
            Self::Connect => "connecting",
            Self::Receive => "receiving",
            Self::Send => "sending",
            Self::Shutdown => "shutting the connection down",
            Self::PeerProcessId => "reading the peer's process id",
        })
    }
}

/// Why the socket client failed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "problem", rename_all = "snake_case")]
pub enum SocketError {
    /// This platform has no AF_UNIX client here.
    Unsupported,
    EmptyPath,
    /// The path has a byte that is not printable ASCII (a NUL or control character
    /// included), or is not Unicode.
    PathNotAscii,
    PathTooLong {
        length_bytes: usize,
        max_bytes: usize,
    },
    TimeoutOutOfRange {
        direction: Direction,
        timeout_ms: u128,
        min_ms: u128,
        max_ms: u128,
    },
    /// A Winsock call failed with this error code.
    Os {
        operation: SocketOperation,
        code: i32,
    },
    /// A receive or send did not complete within its timeout.
    TimedOut {
        direction: Direction,
        timeout_ms: u128,
    },
    /// An earlier receive or send timed out, which leaves the connection in an
    /// indeterminate state; the stream does no further I/O.
    UnusableAfterTimeout,
    /// Winsock reported no usable process id for the peer: a size other than none or a
    /// process id's, or the id 0, which no peer process has.
    PeerProcessIdNotReported {
        returned_bytes: u32,
    },
}

impl fmt::Display for SocketError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsupported => f.write_str("AF_UNIX sockets are not supported on this platform"),
            Self::EmptyPath => f.write_str("the socket path is empty"),
            Self::PathNotAscii => {
                f.write_str("the socket path has a byte that is not printable ASCII")
            }
            Self::PathTooLong {
                length_bytes,
                max_bytes,
            } => write!(
                f,
                "the socket path is {length_bytes} bytes, more than the {max_bytes} a socket \
                 address holds"
            ),
            Self::TimeoutOutOfRange {
                direction,
                timeout_ms,
                min_ms,
                max_ms,
            } => write!(
                f,
                "the {direction} timeout of {timeout_ms} ms is outside {min_ms} to {max_ms} ms"
            ),
            Self::Os { operation, code } => {
                write!(f, "the socket layer failed {operation} with error {code}")
            }
            Self::TimedOut {
                direction,
                timeout_ms,
            } => write!(
                f,
                "the socket's {direction} timed out after {timeout_ms} ms"
            ),
            Self::UnusableAfterTimeout => f.write_str(
                "an earlier receive or send timed out, so the connection is in an \
                 indeterminate state and is not used again",
            ),
            Self::PeerProcessIdNotReported { returned_bytes } => write!(
                f,
                "the socket layer reported no usable process id for the peer ({returned_bytes} bytes)"
            ),
        }
    }
}

impl std::error::Error for SocketError {}

impl SocketError {
    /// The `io::Error` a stream returns for this error: its kind for callers that match
    /// on kinds, and this error inside for callers that read it back with
    /// [`SocketError::from_io`].
    fn into_io(self) -> io::Error {
        let kind = match &self {
            Self::TimedOut { .. } | Self::UnusableAfterTimeout => io::ErrorKind::TimedOut,
            Self::Os { code, .. } => io::Error::from_raw_os_error(*code).kind(),
            _ => io::ErrorKind::Other,
        };
        io::Error::new(kind, self)
    }

    /// The socket error inside an `io::Error` a [`UnixStream`] returned.
    pub fn from_io(error: &io::Error) -> Option<&SocketError> {
        error.get_ref()?.downcast_ref::<SocketError>()
    }
}

/// The receive and send timeouts of a stream, each within [`MIN_SOCKET_TIMEOUT`] and
/// [`MAX_SOCKET_TIMEOUT`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SocketTimeouts {
    receive: Duration,
    send: Duration,
}

impl SocketTimeouts {
    /// Refuses a timeout outside the bounds, zero (Winsock's "forever") included.
    pub fn new(receive: Duration, send: Duration) -> Result<Self, SocketError> {
        for (direction, timeout) in [(Direction::Receive, receive), (Direction::Send, send)] {
            if !(MIN_SOCKET_TIMEOUT..=MAX_SOCKET_TIMEOUT).contains(&timeout) {
                return Err(SocketError::TimeoutOutOfRange {
                    direction,
                    timeout_ms: timeout.as_millis(),
                    min_ms: MIN_SOCKET_TIMEOUT.as_millis(),
                    max_ms: MAX_SOCKET_TIMEOUT.as_millis(),
                });
            }
        }
        Ok(Self { receive, send })
    }

    /// The receive timeout.
    pub fn receive(&self) -> Duration {
        self.receive
    }

    /// The send timeout.
    pub fn send(&self) -> Duration {
        self.send
    }
}

/// The bytes of `path` as a socket address holds them, or why it cannot hold them.
pub fn socket_path_bytes(path: &Path) -> Result<&[u8], SocketError> {
    let text = path.to_str().ok_or(SocketError::PathNotAscii)?;
    if text.is_empty() {
        return Err(SocketError::EmptyPath);
    }
    if !text
        .bytes()
        .all(|byte| byte.is_ascii() && !byte.is_ascii_control())
    {
        return Err(SocketError::PathNotAscii);
    }
    if text.len() > MAX_SOCKET_PATH_BYTES {
        return Err(SocketError::PathTooLong {
            length_bytes: text.len(),
            max_bytes: MAX_SOCKET_PATH_BYTES,
        });
    }
    Ok(text.as_bytes())
}

/// A connected AF_UNIX stream socket. Reading and writing are bounded by its timeouts;
/// the socket is closed when the stream is dropped.
pub struct UnixStream {
    #[cfg(windows)]
    socket: sys::Socket,
    #[cfg(unix)]
    socket: std::os::unix::net::UnixStream,
    #[cfg(not(any(windows, unix)))]
    never: std::convert::Infallible,
    timeouts: SocketTimeouts,
    timed_out: bool,
    nonblocking: bool,
}

impl fmt::Debug for UnixStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UnixStream")
            .field("timeouts", &self.timeouts)
            .field("timed_out", &self.timed_out)
            .field("nonblocking", &self.nonblocking)
            .finish_non_exhaustive()
    }
}

/// Connects to the AF_UNIX stream socket at `path` (see the module notes).
pub fn connect(path: &Path, timeouts: SocketTimeouts) -> Result<UnixStream, SocketError> {
    let bytes = socket_path_bytes(path)?;
    connect_bytes(bytes, timeouts)
}

#[cfg(windows)]
fn connect_bytes(bytes: &[u8], timeouts: SocketTimeouts) -> Result<UnixStream, SocketError> {
    let socket = sys::Socket::connect(bytes, timeouts)?;
    Ok(UnixStream {
        socket,
        timeouts,
        timed_out: false,
        nonblocking: false,
    })
}

/// The socket layer's error of `operation`.
#[cfg(unix)]
fn os_error(operation: SocketOperation, error: &io::Error) -> SocketError {
    SocketError::Os {
        operation,
        code: error.raw_os_error().unwrap_or(0),
    }
}

#[cfg(unix)]
fn connect_bytes(bytes: &[u8], timeouts: SocketTimeouts) -> Result<UnixStream, SocketError> {
    use std::os::unix::ffi::OsStrExt;
    let path = Path::new(std::ffi::OsStr::from_bytes(bytes));
    let socket = std::os::unix::net::UnixStream::connect(path)
        .map_err(|error| os_error(SocketOperation::Connect, &error))?;
    socket
        .set_read_timeout(Some(timeouts.receive()))
        .map_err(|error| os_error(SocketOperation::SetReceiveTimeout, &error))?;
    socket
        .set_write_timeout(Some(timeouts.send()))
        .map_err(|error| os_error(SocketOperation::SetSendTimeout, &error))?;
    Ok(UnixStream {
        socket,
        timeouts,
        timed_out: false,
        nonblocking: false,
    })
}

#[cfg(not(any(windows, unix)))]
fn connect_bytes(_bytes: &[u8], _timeouts: SocketTimeouts) -> Result<UnixStream, SocketError> {
    Err(SocketError::Unsupported)
}

/// What a Unix receive or send that failed means: in blocking mode a call the timeout ended
/// (`EAGAIN`, `ETIMEDOUT`) is a timeout; anything else is the socket layer's error.
#[cfg(unix)]
fn unix_failure(
    error: &io::Error,
    direction: Direction,
    timeout: Duration,
    nonblocking: bool,
) -> Option<SocketError> {
    match error.kind() {
        io::ErrorKind::WouldBlock if nonblocking => None,
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => Some(SocketError::TimedOut {
            direction,
            timeout_ms: timeout.as_millis(),
        }),
        _ => Some(os_error(
            match direction {
                Direction::Receive => SocketOperation::Receive,
                _ => SocketOperation::Send,
            },
            error,
        )),
    }
}

impl UnixStream {
    /// The stream's receive and send timeouts.
    pub fn timeouts(&self) -> SocketTimeouts {
        self.timeouts
    }

    /// Whether the stream is in non-blocking mode.
    pub fn is_nonblocking(&self) -> bool {
        self.nonblocking
    }

    /// Puts the stream in non-blocking mode (module notes): a receive with nothing to read
    /// and a send the socket cannot take now return `WouldBlock`, and no call times out.
    /// Blocking mode with the timeouts is the default.
    pub fn set_nonblocking(&mut self, nonblocking: bool) -> Result<(), SocketError> {
        #[cfg(windows)]
        {
            self.socket.set_nonblocking(nonblocking)?;
            self.nonblocking = nonblocking;
            Ok(())
        }
        #[cfg(unix)]
        {
            self.socket
                .set_nonblocking(nonblocking)
                .map_err(|error| os_error(SocketOperation::SetNonBlocking, &error))?;
            self.nonblocking = nonblocking;
            Ok(())
        }
        #[cfg(not(any(windows, unix)))]
        {
            let _ = nonblocking;
            match self.never {}
        }
    }

    /// Ends `direction` of the connection: no more receiving, sending, or either.
    pub fn shutdown(&self, direction: Direction) -> Result<(), SocketError> {
        #[cfg(windows)]
        {
            self.socket.shutdown(direction)
        }
        #[cfg(unix)]
        {
            self.socket
                .shutdown(match direction {
                    Direction::Receive => std::net::Shutdown::Read,
                    Direction::Send => std::net::Shutdown::Write,
                    Direction::Both => std::net::Shutdown::Both,
                })
                .map_err(|error| os_error(SocketOperation::Shutdown, &error))
        }
        #[cfg(not(any(windows, unix)))]
        {
            let _ = direction;
            match self.never {}
        }
    }

    /// The process id of the peer, as Winsock reports it for an AF_UNIX connection
    /// (`SIO_AF_UNIX_GETPEERPID`): for a client, the process serving the socket. A bare
    /// id: the caller compares it with the process it holds.
    pub fn peer_process_id(&self) -> Result<u32, SocketError> {
        #[cfg(windows)]
        {
            self.socket.peer_process_id()
        }
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            let mut credentials = libc::ucred {
                pid: 0,
                uid: 0,
                gid: 0,
            };
            let mut length = libc::socklen_t::try_from(std::mem::size_of::<libc::ucred>())
                .unwrap_or(libc::socklen_t::MAX);
            // SAFETY: an open socket and a live `ucred` of the stated length.
            let read = unsafe {
                libc::getsockopt(
                    self.socket.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_PEERCRED,
                    (&mut credentials as *mut libc::ucred).cast(),
                    &mut length,
                )
            };
            if read != 0 {
                return Err(os_error(
                    SocketOperation::PeerProcessId,
                    &io::Error::last_os_error(),
                ));
            }
            u32::try_from(credentials.pid)
                .ok()
                .filter(|pid| *pid != 0)
                .ok_or(SocketError::PeerProcessIdNotReported {
                    returned_bytes: length,
                })
        }
        #[cfg(not(any(windows, unix)))]
        {
            match self.never {}
        }
    }

    fn check_usable(&self) -> io::Result<()> {
        if self.timed_out {
            return Err(SocketError::UnusableAfterTimeout.into_io());
        }
        Ok(())
    }

    /// Turns a failed receive or send into its `io::Error`, remembering a timeout. In
    /// non-blocking mode a `WSAEWOULDBLOCK` is `WouldBlock` and nothing is remembered.
    fn failed(&mut self, error: SocketError) -> io::Error {
        if matches!(error, SocketError::TimedOut { .. }) {
            self.timed_out = true;
        }
        error.into_io()
    }
}

impl StreamShutdown for UnixStream {
    /// Ends both directions: the peer sees the end of the stream.
    fn shut_down(&mut self) -> io::Result<()> {
        self.shutdown(Direction::Both).map_err(SocketError::into_io)
    }
}

impl PeerProcess for UnixStream {
    fn peer_process_id(&self) -> io::Result<u32> {
        UnixStream::peer_process_id(self).map_err(SocketError::into_io)
    }
}

/// The [`LinkConnector`] of a QEMU launch's `link.sock`: connects as a client with
/// `timeouts` and switches the stream to non-blocking mode before it is handed to the
/// endpoint check and the session pump (module notes). The timeouts bound nothing once the
/// stream is non-blocking; they apply to the connect's socket options only.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LinkSocketConnector {
    pub timeouts: SocketTimeouts,
}

impl LinkConnector for LinkSocketConnector {
    type Stream = UnixStream;

    fn connect(&mut self, socket: &HostPath) -> io::Result<UnixStream> {
        let mut stream =
            connect(Path::new(socket.as_str()), self.timeouts).map_err(SocketError::into_io)?;
        stream.set_nonblocking(true).map_err(SocketError::into_io)?;
        Ok(stream)
    }
}

impl Read for UnixStream {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.check_usable()?;
        if buffer.is_empty() {
            return Ok(0);
        }
        #[cfg(windows)]
        {
            let timeouts = self.timeouts;
            self.socket
                .receive(buffer, timeouts)
                .map_err(|error| self.failed(error))
        }
        #[cfg(unix)]
        {
            match self.socket.read(buffer) {
                Ok(count) => Ok(count),
                Err(error) => match unix_failure(
                    &error,
                    Direction::Receive,
                    self.timeouts.receive(),
                    self.nonblocking,
                ) {
                    Some(failure) => Err(self.failed(failure)),
                    None => Err(error),
                },
            }
        }
        #[cfg(not(any(windows, unix)))]
        {
            match self.never {}
        }
    }
}

impl Write for UnixStream {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.check_usable()?;
        if buffer.is_empty() {
            return Ok(0);
        }
        #[cfg(windows)]
        {
            let timeouts = self.timeouts;
            self.socket
                .send(buffer, timeouts)
                .map_err(|error| self.failed(error))
        }
        #[cfg(unix)]
        {
            match self.socket.write(buffer) {
                Ok(count) => Ok(count),
                Err(error) => match unix_failure(
                    &error,
                    Direction::Send,
                    self.timeouts.send(),
                    self.nonblocking,
                ) {
                    Some(failure) => Err(self.failed(failure)),
                    None => Err(error),
                },
            }
        }
        #[cfg(not(any(windows, unix)))]
        {
            match self.never {}
        }
    }

    /// Nothing is buffered here: every write is a send.
    fn flush(&mut self) -> io::Result<()> {
        self.check_usable()
    }
}

#[cfg(windows)]
mod sys {
    use std::ptr::{null, null_mut};
    use std::sync::OnceLock;
    use std::time::Duration;

    use windows_sys::Win32::Networking::WinSock::{
        closesocket, connect, ioctlsocket, recv, send, setsockopt, shutdown, WSAGetLastError,
        WSAIoctl, WSASocketW, WSAStartup, AF_UNIX, FIONBIO, INVALID_SOCKET, SD_BOTH, SD_RECEIVE,
        SD_SEND, SIO_AF_UNIX_GETPEERPID, SOCKADDR, SOCKADDR_UN, SOCKET, SOCKET_ERROR, SOCK_STREAM,
        SOL_SOCKET, SO_RCVTIMEO, SO_SNDTIMEO, WSADATA, WSAEINVAL, WSAETIMEDOUT,
        WSA_FLAG_NO_HANDLE_INHERIT, WSA_FLAG_OVERLAPPED,
    };

    use super::{Direction, SocketError, SocketOperation, SocketTimeouts, MAX_SOCKET_PATH_BYTES};

    // `sun_path` holds the longest accepted path and its terminating NUL.
    const _: () = assert!(
        std::mem::size_of::<SOCKADDR_UN>() - std::mem::size_of::<u16>()
            == MAX_SOCKET_PATH_BYTES + 1
    );

    /// Winsock version 2.2.
    const WINSOCK_VERSION: u16 = 0x0202;

    /// Starts Winsock once for this process. Winsock counts starts, and this one is never
    /// undone, as std does for its own sockets.
    pub(super) fn startup() -> Result<(), SocketError> {
        static STARTED: OnceLock<Result<(), i32>> = OnceLock::new();
        let started = STARTED.get_or_init(|| {
            let mut data = WSADATA::default();
            // SAFETY: `data` is a live, writable WSADATA for the call's duration.
            let code = unsafe { WSAStartup(WINSOCK_VERSION, &mut data) };
            if code == 0 {
                Ok(())
            } else {
                Err(code)
            }
        });
        started.map_err(|code| SocketError::Os {
            operation: SocketOperation::Startup,
            code,
        })
    }

    fn last_error(operation: SocketOperation) -> SocketError {
        // SAFETY: reads this thread's last Winsock error; no arguments.
        let code = unsafe { WSAGetLastError() };
        SocketError::Os { operation, code }
    }

    /// A Winsock error, or the typed timeout when the code is `WSAETIMEDOUT`.
    fn io_error(
        operation: SocketOperation,
        direction: Direction,
        timeout: Duration,
    ) -> SocketError {
        match last_error(operation) {
            SocketError::Os { code, .. } if code == WSAETIMEDOUT => SocketError::TimedOut {
                direction,
                timeout_ms: timeout.as_millis(),
            },
            error => error,
        }
    }

    /// An owned, connected Winsock socket, closed once on drop.
    pub(super) struct Socket(SOCKET);

    impl Drop for Socket {
        fn drop(&mut self) {
            // SAFETY: the socket is owned by this value and closed only here; a failed
            // close leaves nothing to do.
            unsafe {
                closesocket(self.0);
            }
        }
    }

    impl Socket {
        pub(super) fn connect(path: &[u8], timeouts: SocketTimeouts) -> Result<Self, SocketError> {
            startup()?;
            let mut address = SOCKADDR_UN {
                sun_family: AF_UNIX,
                ..SOCKADDR_UN::default()
            };
            // The path is checked: at most MAX_SOCKET_PATH_BYTES of printable ASCII, so
            // the last byte of `sun_path` stays NUL.
            for (slot, byte) in address.sun_path.iter_mut().zip(path) {
                *slot = i8::from_ne_bytes([*byte]);
            }
            let invalid = SocketError::Os {
                operation: SocketOperation::Connect,
                code: WSAEINVAL,
            };
            let address_bytes =
                i32::try_from(std::mem::size_of::<SOCKADDR_UN>()).map_err(|_| invalid.clone())?;
            // SAFETY: constant arguments and no protocol info; the result is checked.
            let raw = unsafe {
                WSASocketW(
                    i32::from(AF_UNIX),
                    SOCK_STREAM,
                    0,
                    null(),
                    0,
                    WSA_FLAG_OVERLAPPED | WSA_FLAG_NO_HANDLE_INHERIT,
                )
            };
            if raw == INVALID_SOCKET {
                return Err(last_error(SocketOperation::Create));
            }
            let socket = Self(raw);
            socket.set_timeout(
                SO_RCVTIMEO,
                timeouts.receive(),
                SocketOperation::SetReceiveTimeout,
            )?;
            socket.set_timeout(
                SO_SNDTIMEO,
                timeouts.send(),
                SocketOperation::SetSendTimeout,
            )?;
            // SAFETY: `address` is a live, initialized SOCKADDR_UN of `address_bytes`
            // bytes, read only during the call.
            let connected = unsafe {
                connect(
                    socket.0,
                    (&address as *const SOCKADDR_UN).cast::<SOCKADDR>(),
                    address_bytes,
                )
            };
            if connected != 0 {
                return Err(last_error(SocketOperation::Connect));
            }
            Ok(socket)
        }

        fn set_timeout(
            &self,
            option: i32,
            timeout: Duration,
            operation: SocketOperation,
        ) -> Result<(), SocketError> {
            // The timeouts are bounded to MAX_SOCKET_TIMEOUT, so the milliseconds fit.
            let milliseconds = u32::try_from(timeout.as_millis()).map_err(|_| SocketError::Os {
                operation,
                code: WSAEINVAL,
            })?;
            let size = i32::try_from(std::mem::size_of::<u32>()).map_err(|_| SocketError::Os {
                operation,
                code: WSAEINVAL,
            })?;
            // SAFETY: the option value is a live u32 (Winsock's DWORD milliseconds) of
            // `size` bytes, read only during the call.
            let result = unsafe {
                setsockopt(
                    self.0,
                    SOL_SOCKET,
                    option,
                    (&milliseconds as *const u32).cast::<u8>(),
                    size,
                )
            };
            if result == SOCKET_ERROR {
                return Err(last_error(operation));
            }
            Ok(())
        }

        /// `FIONBIO`: non-blocking mode on, or off.
        pub(super) fn set_nonblocking(&self, nonblocking: bool) -> Result<(), SocketError> {
            let mut mode: u32 = u32::from(nonblocking);
            // SAFETY: `mode` is a live u32 the call reads for FIONBIO.
            if unsafe { ioctlsocket(self.0, FIONBIO, &mut mode) } == SOCKET_ERROR {
                return Err(last_error(SocketOperation::SetNonBlocking));
            }
            Ok(())
        }

        pub(super) fn receive(
            &self,
            buffer: &mut [u8],
            timeouts: SocketTimeouts,
        ) -> Result<usize, SocketError> {
            let length = i32::try_from(buffer.len()).unwrap_or(i32::MAX);
            // SAFETY: `buffer` is live and writable for `length` bytes, which is at most
            // its length.
            let received = unsafe { recv(self.0, buffer.as_mut_ptr(), length, 0) };
            if received == SOCKET_ERROR {
                return Err(io_error(
                    SocketOperation::Receive,
                    Direction::Receive,
                    timeouts.receive(),
                ));
            }
            usize::try_from(received).map_err(|_| SocketError::Os {
                operation: SocketOperation::Receive,
                code: WSAEINVAL,
            })
        }

        pub(super) fn send(
            &self,
            buffer: &[u8],
            timeouts: SocketTimeouts,
        ) -> Result<usize, SocketError> {
            let length = i32::try_from(buffer.len()).unwrap_or(i32::MAX);
            // SAFETY: `buffer` is live and readable for `length` bytes, which is at most
            // its length.
            let sent = unsafe { send(self.0, buffer.as_ptr(), length, 0) };
            if sent == SOCKET_ERROR {
                return Err(io_error(
                    SocketOperation::Send,
                    Direction::Send,
                    timeouts.send(),
                ));
            }
            usize::try_from(sent).map_err(|_| SocketError::Os {
                operation: SocketOperation::Send,
                code: WSAEINVAL,
            })
        }

        pub(super) fn shutdown(&self, direction: Direction) -> Result<(), SocketError> {
            let how = match direction {
                Direction::Receive => SD_RECEIVE,
                Direction::Send => SD_SEND,
                Direction::Both => SD_BOTH,
            };
            // SAFETY: plain call on the owned socket.
            if unsafe { shutdown(self.0, how) } == SOCKET_ERROR {
                return Err(last_error(SocketOperation::Shutdown));
            }
            Ok(())
        }

        /// `SIO_AF_UNIX_GETPEERPID` is afunix.h's `_WSAIOR(IOC_VENDOR, 256)`: it writes
        /// the peer's process id as a ULONG. On this host (Windows 11 26300) the call
        /// succeeds with the id written and zero bytes reported, so a report of zero or
        /// four bytes is accepted and an id of 0 (the buffer untouched) is refused.
        pub(super) fn peer_process_id(&self) -> Result<u32, SocketError> {
            let mut process_id: u32 = 0;
            let mut returned: u32 = 0;
            let size = u32::try_from(std::mem::size_of::<u32>()).map_err(|_| SocketError::Os {
                operation: SocketOperation::PeerProcessId,
                code: WSAEINVAL,
            })?;
            // SAFETY: no input buffer; the output buffer is a live u32 of `size` bytes and
            // `returned` a live u32; the call is synchronous (no overlapped structure and
            // no completion routine).
            let result = unsafe {
                WSAIoctl(
                    self.0,
                    SIO_AF_UNIX_GETPEERPID,
                    null(),
                    0,
                    (&mut process_id as *mut u32).cast(),
                    size,
                    &mut returned,
                    null_mut(),
                    None,
                )
            };
            if result == SOCKET_ERROR {
                return Err(last_error(SocketOperation::PeerProcessId));
            }
            if (returned != 0 && returned != size) || process_id == 0 {
                return Err(SocketError::PeerProcessIdNotReported {
                    returned_bytes: returned,
                });
            }
            Ok(process_id)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn seconds(value: u64) -> Duration {
        Duration::from_secs(value)
    }

    #[test]
    fn socket_paths_are_bounded_by_the_socket_address() {
        let fits = format!(r"C:\{}", "d".repeat(MAX_SOCKET_PATH_BYTES - 3));
        assert_eq!(fits.len(), MAX_SOCKET_PATH_BYTES);
        assert_eq!(
            socket_path_bytes(Path::new(&fits)).unwrap(),
            fits.as_bytes()
        );
        let too_long = format!("{fits}x");
        assert_eq!(
            socket_path_bytes(Path::new(&too_long)),
            Err(SocketError::PathTooLong {
                length_bytes: MAX_SOCKET_PATH_BYTES + 1,
                max_bytes: MAX_SOCKET_PATH_BYTES,
            })
        );
        assert_eq!(MAX_SOCKET_PATH_BYTES, 107);
        assert_eq!(
            socket_path_bytes(Path::new("")),
            Err(SocketError::EmptyPath)
        );
        for bad in [
            "C:\\vm\\q\0.sock",
            "C:\\vm\\\u{e9}.sock",
            "C:\\vm\\a\nb",
            "C:\\vm\\\x7f",
        ] {
            assert_eq!(
                socket_path_bytes(Path::new(bad)),
                Err(SocketError::PathNotAscii),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn a_path_too_long_is_refused_before_any_socket_exists() {
        let too_long = PathBuf::from(format!(r"C:\{}", "d".repeat(MAX_SOCKET_PATH_BYTES)));
        let timeouts = SocketTimeouts::new(seconds(1), seconds(1)).unwrap();
        assert!(matches!(
            connect(&too_long, timeouts),
            Err(SocketError::PathTooLong { .. })
        ));
    }

    #[test]
    fn timeouts_are_bounded_and_never_zero() {
        let timeouts = SocketTimeouts::new(seconds(5), Duration::from_millis(1)).unwrap();
        assert_eq!(timeouts.receive(), seconds(5));
        assert_eq!(timeouts.send(), MIN_SOCKET_TIMEOUT);
        assert!(SocketTimeouts::new(MAX_SOCKET_TIMEOUT, MAX_SOCKET_TIMEOUT).is_ok());
        assert_eq!(
            SocketTimeouts::new(Duration::ZERO, seconds(1)),
            Err(SocketError::TimeoutOutOfRange {
                direction: Direction::Receive,
                timeout_ms: 0,
                min_ms: 1,
                max_ms: 300_000,
            })
        );
        assert!(matches!(
            SocketTimeouts::new(seconds(1), MAX_SOCKET_TIMEOUT + Duration::from_millis(1)),
            Err(SocketError::TimeoutOutOfRange {
                direction: Direction::Send,
                ..
            })
        ));
    }

    #[test]
    fn io_errors_carry_the_typed_socket_error() {
        let error = SocketError::TimedOut {
            direction: Direction::Receive,
            timeout_ms: 5,
        }
        .into_io();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert_eq!(
            SocketError::from_io(&error),
            Some(&SocketError::TimedOut {
                direction: Direction::Receive,
                timeout_ms: 5,
            })
        );
        assert_eq!(SocketError::from_io(&io::Error::other("x")), None);
    }

    /// A minimal AF_UNIX server for the tests: bind, listen, accept, and raw receive and
    /// send on the accepted socket.
    #[cfg(windows)]
    mod listener {
        use std::path::Path;
        use std::ptr::null_mut;

        use windows_sys::Win32::Networking::WinSock::{
            accept, bind, closesocket, listen, recv, send, socket, AF_UNIX, INVALID_SOCKET,
            SOCKADDR, SOCKADDR_UN, SOCKET, SOCK_STREAM,
        };

        pub struct Listener(SOCKET);
        pub struct Accepted(SOCKET);

        impl Listener {
            pub fn bind(path: &Path) -> Self {
                super::super::sys::startup().unwrap();
                let bytes = super::super::socket_path_bytes(path).unwrap();
                let mut address = SOCKADDR_UN {
                    sun_family: AF_UNIX,
                    ..SOCKADDR_UN::default()
                };
                for (slot, byte) in address.sun_path.iter_mut().zip(bytes) {
                    *slot = i8::from_ne_bytes([*byte]);
                }
                let size = i32::try_from(std::mem::size_of::<SOCKADDR_UN>()).unwrap();
                // SAFETY: Winsock calls on a socket owned here; `address` is live and
                // initialized for the bind call.
                unsafe {
                    let raw = socket(i32::from(AF_UNIX), SOCK_STREAM, 0);
                    assert_ne!(raw, INVALID_SOCKET);
                    let address = (&address as *const SOCKADDR_UN).cast::<SOCKADDR>();
                    assert_eq!(bind(raw, address, size), 0);
                    assert_eq!(listen(raw, 1), 0);
                    Self(raw)
                }
            }

            pub fn accept(&self) -> Accepted {
                // SAFETY: accept on the owned listening socket; no address is asked for.
                let raw = unsafe { accept(self.0, null_mut(), null_mut()) };
                assert_ne!(raw, INVALID_SOCKET);
                Accepted(raw)
            }
        }

        impl Accepted {
            pub fn receive(&self, buffer: &mut [u8]) -> i32 {
                let length = i32::try_from(buffer.len()).unwrap();
                // SAFETY: `buffer` is live and writable for `length` bytes.
                unsafe { recv(self.0, buffer.as_mut_ptr(), length, 0) }
            }

            pub fn send(&self, bytes: &[u8]) {
                let length = i32::try_from(bytes.len()).unwrap();
                // SAFETY: `bytes` is live and readable for `length` bytes.
                assert_eq!(unsafe { send(self.0, bytes.as_ptr(), length, 0) }, length);
            }
        }

        impl Drop for Listener {
            fn drop(&mut self) {
                // SAFETY: the socket is owned here and closed once.
                unsafe {
                    closesocket(self.0);
                }
            }
        }

        impl Drop for Accepted {
            fn drop(&mut self) {
                // SAFETY: the socket is owned here and closed once.
                unsafe {
                    closesocket(self.0);
                }
            }
        }
    }

    #[cfg(windows)]
    #[test]
    fn a_stream_reads_writes_shuts_down_and_names_its_peer() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("echo.sock");
        let listener = listener::Listener::bind(&path);
        let server = std::thread::spawn(move || {
            let accepted = listener.accept();
            let mut request = [0u8; 5];
            let mut filled = 0;
            while filled < request.len() {
                let received = accepted.receive(&mut request[filled..]);
                assert!(received > 0, "{received}");
                filled += usize::try_from(received).unwrap();
            }
            assert_eq!(&request, b"ping\n");
            accepted.send(b"pong\n");
            let mut rest = [0u8; 8];
            // The client shut its sending side down: an orderly end of stream.
            assert_eq!(accepted.receive(&mut rest), 0);
        });
        let timeouts = SocketTimeouts::new(seconds(10), seconds(10)).unwrap();
        let mut stream = connect(&path, timeouts).unwrap();
        assert_eq!(stream.peer_process_id().unwrap(), std::process::id());
        stream.write_all(b"ping\n").unwrap();
        stream.flush().unwrap();
        let mut reply = [0u8; 5];
        stream.read_exact(&mut reply).unwrap();
        assert_eq!(&reply, b"pong\n");
        stream.shutdown(Direction::Send).unwrap();
        server.join().unwrap();
        let mut after = [0u8; 4];
        assert_eq!(stream.read(&mut after).unwrap(), 0);
    }

    #[cfg(windows)]
    #[test]
    fn a_receive_timeout_is_typed_and_ends_the_stream() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("silent.sock");
        let listener = listener::Listener::bind(&path);
        let (done, wait) = std::sync::mpsc::channel::<()>();
        let server = std::thread::spawn(move || {
            let accepted = listener.accept();
            // Holds the connection open and silent until the client is done.
            let _ = wait.recv();
            drop(accepted);
        });
        let timeouts = SocketTimeouts::new(Duration::from_millis(50), seconds(10)).unwrap();
        let mut stream = connect(&path, timeouts).unwrap();
        let mut buffer = [0u8; 16];
        let error = stream.read(&mut buffer).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert_eq!(
            SocketError::from_io(&error),
            Some(&SocketError::TimedOut {
                direction: Direction::Receive,
                timeout_ms: 50,
            })
        );
        for error in [
            stream.read(&mut buffer).unwrap_err(),
            stream.write(b"x").unwrap_err(),
        ] {
            assert_eq!(
                SocketError::from_io(&error),
                Some(&SocketError::UnusableAfterTimeout)
            );
        }
        done.send(()).unwrap();
        server.join().unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn a_missing_socket_is_a_typed_connect_failure() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("absent.sock");
        let timeouts = SocketTimeouts::new(seconds(1), seconds(1)).unwrap();
        match connect(&path, timeouts) {
            Err(SocketError::Os {
                operation: SocketOperation::Connect,
                code,
            }) => assert_ne!(code, 0),
            other => panic!("expected a connect failure, got {other:?}"),
        }
    }
}
