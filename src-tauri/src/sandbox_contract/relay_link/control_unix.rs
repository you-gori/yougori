//! The control channel between the engine and a helper process it started (its lifetime
//! supervisor), on Linux: the Unix counterpart of the Windows control pipe, with the same
//! interface (VM part §6.4; VM-W26). A stream socket the engine binds first at a path in a
//! directory only its own account may enter (mode 0700, created or checked here), on which
//! it admits only the process it started (PX1 identity through the peer's `SO_PEERCRED`
//! PID), and on which the helper admits only the engine that named itself (the same check
//! of the server's PID). Lines of text move over it; what they say is the protocol's.
//! After one admission the path is removed, so nothing else can connect.

use std::fmt;
use std::fs;
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use super::pipe_types::{judge_peer, MAX_SOCKET_PATH_BYTES};
pub use super::pipe_types::{PeerRefusal, PipeCall, PipeError};
use crate::foundation::process::ProcessIdentity;

/// The longest line either end keeps before it refuses the peer.
pub const MAX_CONTROL_LINE_BYTES: usize = 256 * 1024;

/// How often a listener looks for a client while it waits.
const ACCEPT_POLL: Duration = Duration::from_millis(10);

/// How often a client tries again while the socket does not exist yet.
const CONNECT_RETRY: Duration = Duration::from_millis(10);

const READ_CHUNK_BYTES: usize = 16 * 1024;

/// A control socket's path: absolute, at most [`MAX_SOCKET_PATH_BYTES`] bytes of ASCII
/// letters, digits, '/', '-', '_' or '.', with no `..` component.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct RelayPipeName(String);

impl RelayPipeName {
    pub fn new(name: impl Into<String>) -> Result<Self, PipeError> {
        let name = name.into();
        let allowed = |c: char| c.is_ascii_alphanumeric() || matches!(c, '/' | '-' | '_' | '.');
        if !name.starts_with('/')
            || name.len() > MAX_SOCKET_PATH_BYTES
            || !name.chars().all(allowed)
            || name.split('/').any(|part| part == "..")
            || Path::new(&name).file_name().is_none()
        {
            return Err(PipeError::InvalidName);
        }
        Ok(Self(name))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn path(&self) -> &Path {
        Path::new(&self.0)
    }
}

impl fmt::Display for RelayPipeName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

fn host_error(call: PipeCall, error: &io::Error) -> PipeError {
    PipeError::HostCall {
        call,
        os_error: error.raw_os_error().map_or(0, i32::unsigned_abs),
    }
}

/// The PID at the other end of `stream` (`SO_PEERCRED`: for a client, the process that
/// connected; for a server, the one that bound the socket).
fn peer_pid(stream: &UnixStream, call: PipeCall) -> Result<u32, PipeError> {
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
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut credentials as *mut libc::ucred).cast(),
            &mut length,
        )
    };
    if read != 0 {
        return Err(host_error(call, &io::Error::last_os_error()));
    }
    u32::try_from(credentials.pid)
        .ok()
        .filter(|pid| *pid != 0)
        .ok_or(PipeError::HostCall { call, os_error: 0 })
}

/// The directory holding `name`, created mode 0700 when absent; an existing one must be
/// a directory (not a link) of this account's alone.
fn private_parent(name: &RelayPipeName) -> Result<(), PipeError> {
    let parent = name.path().parent().ok_or(PipeError::InvalidName)?;
    match fs::symlink_metadata(parent) {
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            fs::create_dir_all(parent).map_err(|error| host_error(PipeCall::CreatePipe, &error))?;
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700))
                .map_err(|error| host_error(PipeCall::CreatePipe, &error))?;
        }
        Err(error) => return Err(host_error(PipeCall::CreatePipe, &error)),
    }
    let metadata =
        fs::symlink_metadata(parent).map_err(|error| host_error(PipeCall::CreatePipe, &error))?;
    // SAFETY: geteuid has no preconditions.
    let me = unsafe { libc::geteuid() };
    if !metadata.is_dir() || metadata.uid() != me || metadata.mode() & 0o077 != 0 {
        return Err(PipeError::HostCall {
            call: PipeCall::CreatePipe,
            os_error: 0,
        });
    }
    Ok(())
}

/// The engine's end before the helper connected.
#[derive(Debug)]
pub struct ControlListener {
    name: RelayPipeName,
    listener: Option<UnixListener>,
}

impl ControlListener {
    /// Binds the socket at `name` in a private directory (module notes); refused if any
    /// file holds the path.
    pub fn create(name: RelayPipeName) -> Result<Self, PipeError> {
        private_parent(&name)?;
        let listener =
            UnixListener::bind(name.path()).map_err(|error| host_error(PipeCall::CreatePipe, &error))?;
        listener
            .set_nonblocking(true)
            .map_err(|error| host_error(PipeCall::CreatePipe, &error))?;
        Ok(Self {
            name,
            listener: Some(listener),
        })
    }

    pub fn name(&self) -> &RelayPipeName {
        &self.name
    }

    /// Waits at most `within` for a client and admits it only if it is exactly `helper`
    /// (PX1 identity); another client is dropped and the listener may accept again. An
    /// admission removes the path.
    pub fn accept(
        &mut self,
        helper: &ProcessIdentity,
        within: Duration,
    ) -> Result<ControlPipe, PipeError> {
        let listener = self.listener.as_ref().ok_or(PipeError::Spent)?;
        let deadline = Instant::now() + within;
        let stream = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    if Instant::now() >= deadline {
                        return Err(PipeError::TimedOut);
                    }
                    std::thread::sleep(ACCEPT_POLL);
                }
                Err(error) => return Err(host_error(PipeCall::Connect, &error)),
            }
        };
        let pid = peer_pid(&stream, PipeCall::ClientProcess)?;
        judge_peer(helper, pid, ProcessIdentity::check)?;
        stream
            .set_nonblocking(false)
            .map_err(|error| host_error(PipeCall::Connect, &error))?;
        self.listener = None;
        let _ = fs::remove_file(self.name.path());
        Ok(ControlPipe {
            stream,
            peer: *helper,
            pending: Vec::new(),
        })
    }
}

impl Drop for ControlListener {
    fn drop(&mut self) {
        if self.listener.is_some() {
            let _ = fs::remove_file(self.name.path());
        }
    }
}

/// One admitted end of the control socket: lines in, lines out.
pub struct ControlPipe {
    stream: UnixStream,
    peer: ProcessIdentity,
    pending: Vec<u8>,
}

impl fmt::Debug for ControlPipe {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ControlPipe")
            .field("peer", &self.peer)
            .finish_non_exhaustive()
    }
}

impl ControlPipe {
    /// The helper's side: connects to `name`, waiting at most `within` while it does not
    /// exist yet, and admits the server only if it is exactly `engine` (PX1 identity
    /// through the PID that bound the socket).
    pub fn connect(
        name: &RelayPipeName,
        engine: &ProcessIdentity,
        within: Duration,
    ) -> Result<Self, PipeError> {
        let deadline = Instant::now() + within;
        let stream = loop {
            match UnixStream::connect(name.path()) {
                Ok(stream) => break stream,
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused
                    ) && Instant::now() < deadline =>
                {
                    std::thread::sleep(CONNECT_RETRY);
                }
                Err(_) if Instant::now() >= deadline => return Err(PipeError::TimedOut),
                Err(error) => return Err(host_error(PipeCall::OpenPipe, &error)),
            }
        };
        let pid = peer_pid(&stream, PipeCall::ServerProcess)?;
        judge_peer(engine, pid, ProcessIdentity::check)?;
        Ok(Self {
            stream,
            peer: *engine,
            pending: Vec::new(),
        })
    }

    /// The process at the other end.
    pub fn peer(&self) -> ProcessIdentity {
        self.peer
    }

    /// Writes `line` (which must end with a newline) within `within`.
    pub fn send_line(&mut self, line: &[u8], within: Duration) -> Result<(), PipeError> {
        if line.len() > MAX_CONTROL_LINE_BYTES {
            return Err(PipeError::HostCall {
                call: PipeCall::Write,
                os_error: 0,
            });
        }
        let deadline = Instant::now() + within;
        let mut written = 0;
        while written < line.len() {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(PipeError::TimedOut);
            }
            self.stream
                .set_write_timeout(Some(left))
                .map_err(|error| host_error(PipeCall::Write, &error))?;
            match self.stream.write(&line[written..]) {
                Ok(0) => return Err(PipeError::Disconnected),
                Ok(count) => written += count,
                Err(error) if matches!(error.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) => {
                    return Err(PipeError::TimedOut)
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) if is_disconnection(&error) => return Err(PipeError::Disconnected),
                Err(error) => return Err(host_error(PipeCall::Write, &error)),
            }
        }
        Ok(())
    }

    /// The next line without its newline, within `within`; `None` when none completed in
    /// time. A line over the bound or a closed socket is an error.
    pub fn read_line(&mut self, within: Duration) -> Result<Option<Vec<u8>>, PipeError> {
        let deadline = Instant::now() + within;
        loop {
            if let Some(index) = self.pending.iter().position(|byte| *byte == b'\n') {
                let line = self.pending[..index].to_vec();
                self.pending.drain(..=index);
                return Ok(Some(line));
            }
            if self.pending.len() > MAX_CONTROL_LINE_BYTES {
                return Err(PipeError::HostCall {
                    call: PipeCall::Read,
                    os_error: 0,
                });
            }
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Ok(None);
            }
            self.stream
                .set_read_timeout(Some(left))
                .map_err(|error| host_error(PipeCall::Read, &error))?;
            let mut buffer = vec![0_u8; READ_CHUNK_BYTES];
            match self.stream.read(&mut buffer) {
                Ok(0) => return Err(PipeError::Disconnected),
                Ok(count) => self.pending.extend_from_slice(&buffer[..count]),
                Err(error) if matches!(error.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) => {
                    return Ok(None)
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) if is_disconnection(&error) => return Err(PipeError::Disconnected),
                Err(error) => return Err(host_error(PipeCall::Read, &error)),
            }
        }
    }
}

fn is_disconnection(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::BrokenPipe | io::ErrorKind::ConnectionReset | io::ErrorKind::NotConnected
    )
}

/// Where a control socket of this engine is made: `directory` (private, created when
/// absent) and a short name of the helper's kind, the engine's PID and a fresh suffix.
pub fn socket_in(directory: &Path, kind: &str) -> Result<RelayPipeName, PipeError> {
    let suffix = uuid::Uuid::new_v4().simple().to_string();
    let path: PathBuf = directory.join(format!("{kind}-{}-{}.sock", std::process::id(), &suffix[..12]));
    RelayPipeName::new(path.to_str().ok_or(PipeError::InvalidName)?.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// PROVES two ends in this process: the listener admits this process, lines go both
    /// ways within their bounds, nothing within a short wait is `None`, a closed end is an
    /// error on the other, and the path is gone after the admission; a name that is not an
    /// absolute, plain, short path is refused.
    #[test]
    fn a_control_socket_carries_lines_between_admitted_ends() {
        let me = ProcessIdentity::holder_of(std::process::id()).unwrap().unwrap();
        let directory = std::env::temp_dir().join(format!("yg-control-{}", std::process::id()));
        let _ = fs::remove_dir_all(&directory);
        let name = socket_in(&directory, "t").unwrap();
        let mut listener = ControlListener::create(name.clone()).unwrap();
        assert_eq!(
            fs::metadata(&directory).unwrap().permissions().mode() & 0o777,
            0o700
        );
        let client_name = name.clone();
        let client = std::thread::spawn(move || {
            let mut pipe = ControlPipe::connect(&client_name, &me, Duration::from_secs(5)).unwrap();
            pipe.send_line(b"hello from the helper\n", Duration::from_secs(5)).unwrap();
            let line = pipe.read_line(Duration::from_secs(5)).unwrap().unwrap();
            assert_eq!(line, b"hello from the engine");
            assert!(pipe.read_line(Duration::from_millis(20)).unwrap().is_none());
            pipe.send_line(b"bye\n", Duration::from_secs(5)).unwrap();
        });
        let mut server = listener.accept(&me, Duration::from_secs(5)).unwrap();
        assert!(!Path::new(name.as_str()).exists(), "the path is removed once admitted");
        assert_eq!(server.read_line(Duration::from_secs(5)).unwrap().unwrap(), b"hello from the helper");
        server.send_line(b"hello from the engine\n", Duration::from_secs(5)).unwrap();
        assert_eq!(server.read_line(Duration::from_secs(5)).unwrap().unwrap(), b"bye");
        client.join().unwrap();
        assert!(matches!(server.read_line(Duration::from_secs(5)), Err(PipeError::Disconnected)));
        for bad in ["relative.sock", "/a/../b.sock", "/a/b c.sock", "/"] {
            assert!(RelayPipeName::new(bad).is_err(), "{bad}");
        }
        assert!(RelayPipeName::new(format!("/{}", "a".repeat(MAX_SOCKET_PATH_BYTES))).is_err());
        fs::remove_dir_all(&directory).unwrap();
    }

    /// PROVES a client that is not the named helper is refused at the admission (another
    /// PID), and the listener then waits for the right one.
    #[test]
    fn another_process_is_refused_at_the_admission() {
        let me = ProcessIdentity::holder_of(std::process::id()).unwrap().unwrap();
        let other = ProcessIdentity {
            pid: me.pid.wrapping_add(1),
            start_time_ticks: me.start_time_ticks,
        };
        let directory = std::env::temp_dir().join(format!("yg-control-o-{}", std::process::id()));
        let _ = fs::remove_dir_all(&directory);
        let name = socket_in(&directory, "t").unwrap();
        let mut listener = ControlListener::create(name.clone()).unwrap();
        let client_name = name.clone();
        let client = std::thread::spawn(move || {
            let _stream = UnixStream::connect(client_name.as_str()).unwrap();
            std::thread::sleep(Duration::from_millis(200));
        });
        assert!(matches!(
            listener.accept(&other, Duration::from_secs(5)),
            Err(PipeError::Peer(PeerRefusal::OtherProcess { .. }))
        ));
        assert!(Path::new(name.as_str()).exists(), "not admitted: the path stays");
        client.join().unwrap();
        drop(listener);
        assert!(!Path::new(name.as_str()).exists());
        fs::remove_dir_all(&directory).unwrap();
    }
}
