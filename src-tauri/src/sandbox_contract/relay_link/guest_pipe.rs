//! The guest pipe: the engine's link egress channel carried to the confined relay's guest
//! port (M06's guest transport for M09E's relay; docs/combined-gpu-memory-and-vm-sandbox-plan.md,
//! VM part §3.1: the relay is the one process that parses the guest's bytes; VM-W11).
//!
//! The engine owns a sandbox's link and sees the guest open an egress stream to a named
//! destination and send plaintext HTTP on it. The relay, confined in its AppContainer, must
//! read those bytes and nothing else of the host. So the engine creates one named pipe per
//! relay ([`GuestPipeListener`]), with the same protected security the relay's link pipe has
//! (owner and the relay's AppContainer SID, a low label), admits only the relay process by
//! PX1 identity, and carries each egress stream over it as a numbered guest connection in
//! bounded, versioned frames ([`GuestFrame`]): the open with its endpoint, the guest's bytes,
//! the guest's end; back, the relay's bytes and its end. The relay's side
//! ([`PipeGuestPort`]) opens the pipe by the name its handoff carries, admits the server by
//! the engine's PID (a confined process cannot read another's creation time; the handoff
//! names the PID the executor saw) and is the relay's [`GuestPort`].
//!
//! No byte is parsed here: the frames carry opaque bytes between the link and the relay.
//! Nothing secret crosses this pipe (the guest's bytes are the sandbox's own traffic, and
//! the credential never reaches the relay).

use std::collections::BTreeSet;
use std::fmt;
use std::os::windows::io::{AsRawHandle, OwnedHandle};
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{ERROR_NO_DATA, ERROR_PIPE_CONNECTED, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Storage::FileSystem::{
    ReadFile, FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED, PIPE_ACCESS_DUPLEX,
};
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, GetNamedPipeClientProcessId, GetNamedPipeServerProcessId,
    PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_WAIT,
};

use super::pipe::{
    admit, is_disconnection, left, open_client, write_all, PeerRefusal, PipeCall, PipeError,
    RelayPipeName,
};
use super::pipe_container::{OwnerAndContainer, CONTAINER_PIPE_ACCESS};
use super::pipe_os::{complete, host_error, new_event, owned, Incomplete};
use crate::foundation::process::ProcessIdentity;
use crate::sandbox_contract::relay_process::{
    GuestConnection, GuestEndpoint, GuestEvent, GuestPort, GuestPortError,
};

/// The frame format.
pub const GUEST_PIPE_VERSION: u8 = 1;

/// The longest payload of one frame.
pub const MAX_GUEST_FRAME_BYTES: usize = 65_536;

/// The frame header: version, kind, connection (8), length (4).
const HEADER_BYTES: usize = 14;

const PIPE_BUFFER_BYTES: u32 = 64 * 1024;
const READ_CHUNK_BYTES: usize = 64 * 1024;

/// One frame of the guest pipe.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GuestFrame {
    /// The guest opened `connection` to `endpoint` (engine to relay).
    Open { connection: u64, endpoint: String },
    /// Bytes the guest sent on `connection` (engine to relay).
    Data { connection: u64, bytes: Vec<u8> },
    /// The guest ended its sending side of `connection` (engine to relay).
    Close { connection: u64 },
    /// Bytes for the guest on `connection` (relay to engine).
    RelayData { connection: u64, bytes: Vec<u8> },
    /// The relay ended `connection` (relay to engine).
    RelayEnd { connection: u64 },
}

impl GuestFrame {
    const fn kind(&self) -> u8 {
        match self {
            Self::Open { .. } => 1,
            Self::Data { .. } => 2,
            Self::Close { .. } => 3,
            Self::RelayData { .. } => 4,
            Self::RelayEnd { .. } => 5,
        }
    }

    pub fn connection(&self) -> u64 {
        match self {
            Self::Open { connection, .. }
            | Self::Data { connection, .. }
            | Self::Close { connection }
            | Self::RelayData { connection, .. }
            | Self::RelayEnd { connection } => *connection,
        }
    }

    fn payload(&self) -> &[u8] {
        match self {
            Self::Open { endpoint, .. } => endpoint.as_bytes(),
            Self::Data { bytes, .. } | Self::RelayData { bytes, .. } => bytes,
            Self::Close { .. } | Self::RelayEnd { .. } => &[],
        }
    }

    /// The frame's bytes; refused when the payload is over the bound.
    pub fn encode(&self) -> Result<Vec<u8>, GuestPipeError> {
        let payload = self.payload();
        if payload.len() > MAX_GUEST_FRAME_BYTES {
            return Err(GuestPipeError::Oversize {
                length: payload.len(),
            });
        }
        let mut out = Vec::with_capacity(HEADER_BYTES + payload.len());
        out.push(GUEST_PIPE_VERSION);
        out.push(self.kind());
        out.extend_from_slice(&self.connection().to_be_bytes());
        out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        out.extend_from_slice(payload);
        Ok(out)
    }

    /// One frame from the front of `pending`, if a whole one is there.
    pub fn take(pending: &mut Vec<u8>) -> Result<Option<Self>, GuestPipeError> {
        if pending.len() < HEADER_BYTES {
            return Ok(None);
        }
        if pending[0] != GUEST_PIPE_VERSION {
            return Err(GuestPipeError::UnsupportedVersion { found: pending[0] });
        }
        let kind = pending[1];
        let connection = u64::from_be_bytes(pending[2..10].try_into().unwrap_or([0; 8]));
        let length = u32::from_be_bytes(pending[10..14].try_into().unwrap_or([0; 4])) as usize;
        if length > MAX_GUEST_FRAME_BYTES {
            return Err(GuestPipeError::Oversize { length });
        }
        if pending.len() < HEADER_BYTES + length {
            return Ok(None);
        }
        let payload: Vec<u8> = pending[HEADER_BYTES..HEADER_BYTES + length].to_vec();
        pending.drain(..HEADER_BYTES + length);
        let frame = match kind {
            1 => Self::Open {
                connection,
                endpoint: String::from_utf8(payload).map_err(|_| GuestPipeError::Malformed)?,
            },
            2 => Self::Data {
                connection,
                bytes: payload,
            },
            3 if length == 0 => Self::Close { connection },
            4 => Self::RelayData {
                connection,
                bytes: payload,
            },
            5 if length == 0 => Self::RelayEnd { connection },
            other => return Err(GuestPipeError::UnknownKind { kind: other }),
        };
        Ok(Some(frame))
    }
}

/// Why the guest pipe failed.
#[derive(Debug)]
pub enum GuestPipeError {
    Pipe(PipeError),
    Malformed,
    Oversize { length: usize },
    UnknownKind { kind: u8 },
    UnsupportedVersion { found: u8 },
}

impl fmt::Display for GuestPipeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pipe(error) => fmt::Display::fmt(error, f),
            Self::Malformed => f.write_str("a guest pipe frame is malformed"),
            Self::Oversize { length } => {
                write!(f, "a guest pipe frame of {length} bytes is over the bound")
            }
            Self::UnknownKind { kind } => write!(f, "a guest pipe frame has unknown kind {kind}"),
            Self::UnsupportedVersion { found } => {
                write!(
                    f,
                    "a guest pipe frame has version {found}, not {GUEST_PIPE_VERSION}"
                )
            }
        }
    }
}

impl std::error::Error for GuestPipeError {}

impl From<PipeError> for GuestPipeError {
    fn from(error: PipeError) -> Self {
        Self::Pipe(error)
    }
}

/// The guest pipe's name for one relay: `\\.\pipe\yougori-guest-<pid>-<start ticks>`, which
/// the relay derives from the handoff's identity of itself and the engine from the executor's
/// reply.
pub fn guest_pipe_name(relay: &ProcessIdentity) -> Result<RelayPipeName, PipeError> {
    RelayPipeName::new(format!(
        r"\\.\pipe\yougori-guest-{}-{}",
        relay.pid, relay.start_time_ticks
    ))
}

/// Reads whole frames from an open pipe end.
struct FrameReader {
    pending: Vec<u8>,
}

impl FrameReader {
    /// The next frame within `within`; `None` when none completed in time.
    fn next(
        &mut self,
        pipe: &OwnedHandle,
        event: &OwnedHandle,
        within: Duration,
    ) -> Result<Option<GuestFrame>, GuestPipeError> {
        let deadline = Instant::now().checked_add(within);
        loop {
            if let Some(frame) = GuestFrame::take(&mut self.pending)? {
                return Ok(Some(frame));
            }
            let remaining = left(deadline, within);
            if remaining.is_zero() {
                return Ok(None);
            }
            let mut buffer = vec![0_u8; READ_CHUNK_BYTES];
            let length = u32::try_from(buffer.len()).unwrap_or(u32::MAX);
            // SAFETY: `buffer` holds `length` writable bytes and outlives the operation,
            // which `complete` waits for.
            let result = complete(pipe, event, remaining, |raw, overlapped| unsafe {
                ReadFile(
                    raw,
                    buffer.as_mut_ptr(),
                    length,
                    std::ptr::null_mut(),
                    overlapped,
                )
            });
            match result {
                Ok(0) => return Err(PipeError::Disconnected.into()),
                Ok(count) => {
                    let count = usize::try_from(count).unwrap_or(0).min(buffer.len());
                    self.pending.extend_from_slice(&buffer[..count]);
                }
                Err(Incomplete::TimedOut) => return Ok(None),
                Err(Incomplete::Failed(os_error)) if is_disconnection(os_error) => {
                    return Err(PipeError::Disconnected.into())
                }
                Err(Incomplete::Failed(os_error)) => {
                    return Err(PipeError::HostCall {
                        call: PipeCall::Read,
                        os_error,
                    }
                    .into())
                }
            }
        }
    }
}

/// The engine's end before the relay connected.
#[derive(Debug)]
pub struct GuestPipeListener {
    name: RelayPipeName,
    pipe: Option<OwnedHandle>,
    event: OwnedHandle,
}

impl GuestPipeListener {
    /// Creates the pipe's one instance for the relay confined in the AppContainer `container`
    /// (its binary SID): owner and that container may open it, the label is low, remote
    /// clients are rejected, and no other instance of the name may exist.
    pub fn create(name: RelayPipeName, container: &[u8]) -> Result<Self, PipeError> {
        let mut security = OwnerAndContainer::new(container)?;
        let attributes = security.attributes();
        let wide = name.wide();
        // SAFETY: `wide` is a NUL-terminated name and `attributes` points into the security
        // descriptor, both live for the call.
        let raw = unsafe {
            CreateNamedPipeW(
                wide.as_ptr(),
                PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                1,
                PIPE_BUFFER_BYTES,
                PIPE_BUFFER_BYTES,
                0,
                &attributes,
            )
        };
        if raw == INVALID_HANDLE_VALUE {
            return Err(host_error(PipeCall::CreatePipe));
        }
        let pipe = owned(raw).ok_or_else(|| host_error(PipeCall::CreatePipe))?;
        Ok(Self {
            name,
            pipe: Some(pipe),
            event: new_event()?,
        })
    }

    pub fn name(&self) -> &RelayPipeName {
        &self.name
    }

    /// Waits at most `within` for a client and admits it only if it is exactly `relay` (PX1
    /// identity); another client is refused and the listener may accept again.
    pub fn accept(
        &mut self,
        relay: &ProcessIdentity,
        within: Duration,
    ) -> Result<GuestPipeServer, PipeError> {
        let pipe = self.pipe.as_ref().ok_or(PipeError::Spent)?;
        // SAFETY: the pipe handle is open; `complete` keeps `overlapped` live until the
        // operation ends.
        let connected = complete(pipe, &self.event, within, |raw, overlapped| unsafe {
            ConnectNamedPipe(raw, overlapped)
        });
        let refused = match connected {
            Ok(_) | Err(Incomplete::Failed(ERROR_PIPE_CONNECTED)) => admit(
                pipe,
                relay,
                GetNamedPipeClientProcessId,
                PipeCall::ClientProcess,
            )
            .err(),
            Err(Incomplete::TimedOut) => return Err(PipeError::TimedOut),
            Err(Incomplete::Failed(ERROR_NO_DATA)) => Some(PipeError::Disconnected),
            Err(Incomplete::Failed(os_error)) => {
                return Err(PipeError::HostCall {
                    call: PipeCall::Connect,
                    os_error,
                })
            }
        };
        if let Some(error) = refused {
            // SAFETY: the pipe handle is open; a refused client is disconnected so the
            // instance may accept again.
            unsafe { windows_sys::Win32::System::Pipes::DisconnectNamedPipe(pipe.as_raw_handle()) };
            return Err(error);
        }
        let pipe = self.pipe.take().ok_or(PipeError::Spent)?;
        Ok(GuestPipeServer {
            pipe,
            event: new_event()?,
            relay: *relay,
            reader: FrameReader {
                pending: Vec::new(),
            },
        })
    }
}

/// The engine's end of an admitted guest pipe.
pub struct GuestPipeServer {
    pipe: OwnedHandle,
    event: OwnedHandle,
    relay: ProcessIdentity,
    reader: FrameReader,
}

impl fmt::Debug for GuestPipeServer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GuestPipeServer")
            .field("relay", &self.relay)
            .finish_non_exhaustive()
    }
}

impl GuestPipeServer {
    pub fn relay(&self) -> ProcessIdentity {
        self.relay
    }

    /// Writes `frame` within `within`.
    pub fn send(&mut self, frame: &GuestFrame, within: Duration) -> Result<(), GuestPipeError> {
        let bytes = frame.encode()?;
        write_all(&self.pipe, &self.event, &bytes, within)?;
        Ok(())
    }

    /// The relay's next frame within `within`; `None` when none came.
    pub fn receive(&mut self, within: Duration) -> Result<Option<GuestFrame>, GuestPipeError> {
        self.reader.next(&self.pipe, &self.event, within)
    }
}

/// The relay's end: the confined relay's [`GuestPort`] over the guest pipe (module notes).
pub struct PipeGuestPort {
    pipe: OwnedHandle,
    event: OwnedHandle,
    reader: FrameReader,
    open: BTreeSet<u64>,
    send_within: Duration,
    ended: bool,
}

impl fmt::Debug for PipeGuestPort {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PipeGuestPort")
            .field("open", &self.open.len())
            .finish_non_exhaustive()
    }
}

impl PipeGuestPort {
    /// Opens the pipe `name`, waiting at most `within` while it does not exist yet or its
    /// instance is busy, and admits the server only if its PID is `engine`'s. A confined
    /// relay cannot read another process's creation time, so the PID is the check, as it is
    /// for the relay's creator on its link pipe; the engine's PID names no other process
    /// while the engine lives, and the relay's executor ends the relay when the engine goes.
    pub fn connect(
        name: &RelayPipeName,
        engine: u32,
        within: Duration,
        send_within: Duration,
    ) -> Result<Self, PipeError> {
        // Ask for exactly the access granted to the AppContainer, as the broker link
        // does. GENERIC_WRITE also requests attributes/instance rights absent from
        // this deliberately narrow DACL, so Windows would reject the real relay.
        let pipe = open_client(name, CONTAINER_PIPE_ACCESS, true, within)?;
        let mut server = 0_u32;
        // SAFETY: the pipe handle is open and connected; `server` is live.
        if unsafe { GetNamedPipeServerProcessId(pipe.as_raw_handle(), &mut server) } == 0 {
            return Err(host_error(PipeCall::ServerProcess));
        }
        if server != engine {
            return Err(PipeError::Peer(PeerRefusal::OtherProcess { pid: server }));
        }
        Ok(Self {
            pipe,
            event: new_event()?,
            reader: FrameReader {
                pending: Vec::new(),
            },
            open: BTreeSet::new(),
            send_within,
            ended: false,
        })
    }

    fn send(&mut self, frame: &GuestFrame) -> Result<(), GuestPortError> {
        let bytes = frame.encode().map_err(|error| GuestPortError {
            detail: error.to_string(),
        })?;
        write_all(&self.pipe, &self.event, &bytes, self.send_within).map_err(|error| {
            GuestPortError {
                detail: error.to_string(),
            }
        })
    }
}

impl GuestPort for PipeGuestPort {
    fn next_event(&mut self, within: Duration) -> Result<GuestEvent, GuestPortError> {
        if self.ended {
            return Ok(GuestEvent::Ended);
        }
        let frame = match self.reader.next(&self.pipe, &self.event, within) {
            Ok(Some(frame)) => frame,
            Ok(None) => return Ok(GuestEvent::Idle),
            Err(GuestPipeError::Pipe(PipeError::Disconnected)) => {
                self.ended = true;
                return Ok(GuestEvent::Ended);
            }
            Err(error) => {
                return Err(GuestPortError {
                    detail: error.to_string(),
                })
            }
        };
        Ok(match frame {
            GuestFrame::Open {
                connection,
                endpoint,
            } => {
                let endpoint = GuestEndpoint::new(endpoint).map_err(|error| GuestPortError {
                    detail: format!("the endpoint name was refused: {error}"),
                })?;
                self.open.insert(connection);
                GuestEvent::Opened {
                    connection: GuestConnection::new(connection),
                    endpoint,
                }
            }
            GuestFrame::Data { connection, bytes } => GuestEvent::Data {
                connection: GuestConnection::new(connection),
                bytes,
            },
            GuestFrame::Close { connection } => GuestEvent::Closed {
                connection: GuestConnection::new(connection),
            },
            GuestFrame::RelayData { .. } | GuestFrame::RelayEnd { .. } => {
                return Err(GuestPortError {
                    detail: "the engine sent a relay-side frame".to_owned(),
                })
            }
        })
    }

    fn write(&mut self, connection: GuestConnection, bytes: &[u8]) -> Result<(), GuestPortError> {
        for chunk in bytes.chunks(MAX_GUEST_FRAME_BYTES) {
            self.send(&GuestFrame::RelayData {
                connection: connection.get(),
                bytes: chunk.to_vec(),
            })?;
        }
        Ok(())
    }

    fn end(&mut self, connection: GuestConnection) {
        self.open.remove(&connection.get());
        let _ = self.send(&GuestFrame::RelayEnd {
            connection: connection.get(),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_round_trip_and_bounds_hold() {
        let frames = vec![
            GuestFrame::Open {
                connection: 7,
                endpoint: "provider".to_owned(),
            },
            GuestFrame::Data {
                connection: 7,
                bytes: b"GET / HTTP/1.1\r\n\r\n".to_vec(),
            },
            GuestFrame::Close { connection: 7 },
            GuestFrame::RelayData {
                connection: 7,
                bytes: b"HTTP/1.1 200 OK\r\n\r\n".to_vec(),
            },
            GuestFrame::RelayEnd { connection: 7 },
        ];
        let mut wire = Vec::new();
        for frame in &frames {
            wire.extend(frame.encode().unwrap());
        }
        // Fed in two halves: no frame is taken before it is whole.
        let split = wire.len() / 2;
        let mut pending = wire[..split].to_vec();
        let mut decoded = Vec::new();
        while let Some(frame) = GuestFrame::take(&mut pending).unwrap() {
            decoded.push(frame);
        }
        pending.extend_from_slice(&wire[split..]);
        while let Some(frame) = GuestFrame::take(&mut pending).unwrap() {
            decoded.push(frame);
        }
        assert_eq!(decoded, frames);
        assert!(pending.is_empty());
        // Bounds and strictness.
        assert!(matches!(
            GuestFrame::Data {
                connection: 1,
                bytes: vec![0; MAX_GUEST_FRAME_BYTES + 1]
            }
            .encode(),
            Err(GuestPipeError::Oversize { .. })
        ));
        let mut bad_version = GuestFrame::Close { connection: 1 }.encode().unwrap();
        bad_version[0] = 9;
        assert!(matches!(
            GuestFrame::take(&mut bad_version),
            Err(GuestPipeError::UnsupportedVersion { found: 9 })
        ));
        let mut bad_kind = GuestFrame::Close { connection: 1 }.encode().unwrap();
        bad_kind[1] = 42;
        assert!(matches!(
            GuestFrame::take(&mut bad_kind),
            Err(GuestPipeError::UnknownKind { kind: 42 })
        ));
        let mut huge = GuestFrame::Close { connection: 1 }.encode().unwrap();
        huge[10..14].copy_from_slice(&(MAX_GUEST_FRAME_BYTES as u32 + 1).to_be_bytes());
        assert!(matches!(
            GuestFrame::take(&mut huge),
            Err(GuestPipeError::Oversize { .. })
        ));
        let name = guest_pipe_name(&ProcessIdentity {
            pid: 4242,
            start_time_ticks: 99,
        })
        .unwrap();
        assert_eq!(name.as_str(), r"\\.\pipe\yougori-guest-4242-99");
    }

    /// A real pipe between two ends of this process: the server admits this process as the
    /// relay, the port sees the guest's open, bytes and close, and the relay's answer and end
    /// come back.
    #[test]
    fn a_guest_pipe_carries_connections_both_ways_between_two_ends_of_this_process() {
        let me = ProcessIdentity::holder_of(std::process::id())
            .unwrap()
            .unwrap();
        let name = RelayPipeName::new(format!(
            r"\\.\pipe\yougori-guest-test-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4().simple()
        ))
        .unwrap();
        // This process is no AppContainer; the owner-only listener of the link pipe module
        // is the security the test needs, through the same creation path.
        let mut listener =
            match GuestPipeListener::create(name.clone(), &app_container_sid_for_tests()) {
                Ok(listener) => listener,
                Err(error) => panic!("listener: {error}"),
            };
        let client_name = name.clone();
        let client = std::thread::spawn(move || {
            let mut port = PipeGuestPort::connect(
                &client_name,
                std::process::id(),
                Duration::from_secs(5),
                Duration::from_secs(5),
            )
            .unwrap();
            let mut seen = Vec::new();
            loop {
                match port.next_event(Duration::from_secs(5)).unwrap() {
                    GuestEvent::Idle => continue,
                    GuestEvent::Closed { connection } => {
                        seen.push("closed".to_owned());
                        port.write(connection, b"HTTP/1.1 200 OK\r\n\r\n").unwrap();
                        port.end(connection);
                        break;
                    }
                    GuestEvent::Opened {
                        connection,
                        endpoint,
                    } => {
                        assert_eq!(connection, GuestConnection::new(3));
                        seen.push(format!("opened {endpoint}"));
                    }
                    GuestEvent::Data { bytes, .. } => {
                        seen.push(format!("data {}", bytes.len()));
                    }
                    GuestEvent::Ended => break,
                }
            }
            seen
        });
        let mut server = listener.accept(&me, Duration::from_secs(5)).unwrap();
        server
            .send(
                &GuestFrame::Open {
                    connection: 3,
                    endpoint: "provider".to_owned(),
                },
                Duration::from_secs(5),
            )
            .unwrap();
        server
            .send(
                &GuestFrame::Data {
                    connection: 3,
                    bytes: b"GET / HTTP/1.1\r\nhost: api.example.com\r\n\r\n".to_vec(),
                },
                Duration::from_secs(5),
            )
            .unwrap();
        server
            .send(&GuestFrame::Close { connection: 3 }, Duration::from_secs(5))
            .unwrap();
        let mut answer = Vec::new();
        let mut ended = false;
        while !ended {
            match server.receive(Duration::from_secs(5)).unwrap() {
                Some(GuestFrame::RelayData { connection, bytes }) => {
                    assert_eq!(connection, 3);
                    answer.extend(bytes);
                }
                Some(GuestFrame::RelayEnd { connection }) => {
                    assert_eq!(connection, 3);
                    ended = true;
                }
                Some(other) => panic!("unexpected frame {other:?}"),
                None => panic!("the relay side never answered"),
            }
        }
        assert_eq!(answer, b"HTTP/1.1 200 OK\r\n\r\n");
        let seen = client.join().unwrap();
        assert_eq!(seen, vec!["opened provider", "data 41", "closed"]);
    }

    /// A SID of the AppContainer kind for the listener's DACL: the test is no AppContainer,
    /// so the grant it adds is to nobody present, and the owner's entry is what admits this
    /// process. (`S-1-15-2-1`: the "ALL APPLICATION PACKAGES" SID.)
    fn app_container_sid_for_tests() -> Vec<u8> {
        // Revision 1, one sub-authority after the package authority: S-1-15-2-1.
        let mut sid = vec![1_u8, 2, 0, 0, 0, 0, 0, 15];
        sid.extend_from_slice(&2_u32.to_le_bytes());
        sid.extend_from_slice(&1_u32.to_le_bytes());
        sid
    }
}
