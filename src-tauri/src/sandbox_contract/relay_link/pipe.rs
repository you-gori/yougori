//! The link's named-pipe adapter on Windows (M09C; VM part §3.1: only the registered relay
//! process can use the channel; VM part §6.4 and VM-CP-19: a process is its PID and
//! creation time, and a reused PID is never taken for it). Thin over the sans-IO
//! [`LinkSession`]: it moves bytes and checks peers, and every frame rule is the session's.
//!
//! [`RelayPipeListener::create`] makes the pipe's one instance, refused if any instance of
//! the name exists (`FILE_FLAG_FIRST_PIPE_INSTANCE`, at most one instance), with a
//! protected DACL that grants the current user alone, in [`RELAY_PIPE_MODE`]: byte
//! stream, blocking, `PIPE_REJECT_REMOTE_CLIENTS`. [`RelayPipeListener::accept`] waits a
//! bounded time for a client, reads its PID with `GetNamedPipeClientProcessId` and checks
//! through PX1 ([`ProcessIdentity::check`]) that it is exactly the relay process of the
//! [`LinkBinding`], PID and creation time (`judge_peer`). Anything else is disconnected
//! before a byte is read, and the next accept waits for another client, so a squatting
//! client cannot keep the relay out. [`connect_relay`] is the relay's side: it opens the
//! pipe at identification level only, so the server cannot impersonate it, and checks the
//! server's PID against the broker's identity the same way.
//!
//! For a relay confined in an AppContainer (M09E), which inherits nothing:
//! [`RelayPipeListener::create_for_container`] also grants the relay's AppContainer read
//! and write under a low label; the pipe is named after the relay's PX1 identity
//! ([`RelayPipeName::for_relay`]); [`open_confined_relay`] opens it from the relay, waiting
//! for it to exist, and admits the server only if it is the relay's creator; and
//! [`RelayPipeListener::accept_with_handoff`] writes the relay's handoff to the admitted
//! relay ahead of the first frame, which [`HandoverPipe::read_handoff`] reads, bounded,
//! before [`HandoverPipe::into_link`] opens the link.
//!
//! A [`LinkPipe`] then carries frames: [`LinkPipe::send`] seals and writes one,
//! [`LinkPipe::receive`] reads until the [`FrameDecoder`] has a frame and hands it to the
//! session. Every wait is bounded. A refused frame, a frame cut short by a failed send or
//! receive, or a disconnection ends the session; a receive that times out keeps what
//! arrived and may be called again.
//!
//! The check binds the process that opened the client end. A relay that passed its handle
//! to another process would be that process's proxy, which the relay's confinement
//! (outside this module) rules out.

use std::fmt;
use std::os::windows::io::{AsRawHandle, OwnedHandle};
use std::ptr::{null, null_mut};
use std::thread;
use std::time::{Duration, Instant};

use windows_sys::core::BOOL;
use windows_sys::Win32::Foundation::{
    ERROR_BROKEN_PIPE, ERROR_FILE_NOT_FOUND, ERROR_NO_DATA, ERROR_PIPE_BUSY, ERROR_PIPE_CONNECTED,
    ERROR_PIPE_NOT_CONNECTED, GENERIC_READ, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, ReadFile, WriteFile, FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED,
    OPEN_EXISTING, PIPE_ACCESS_DUPLEX, SECURITY_IDENTIFICATION, SECURITY_SQOS_PRESENT,
};
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, GetNamedPipeClientProcessId,
    GetNamedPipeServerProcessId, PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE,
    PIPE_WAIT,
};

use super::frame::FrameDecoder;
use super::pipe_container::{OwnerAndContainer, CONTAINER_PIPE_ACCESS};
pub(super) use super::pipe_types::judge_peer;
pub use super::pipe_types::{PeerRefusal, PipeCall, PipeError};
use super::pipe_types::{LOCAL_PIPE_PREFIX, MAX_PIPE_NAME_CHARS};
use super::pipe_os::{complete, host_error, last_error, new_event, owned, Incomplete, OwnerOnly};
use super::session::{
    BrokerLink, BrokerSide, LinkBinding, LinkEnd, LinkKey, LinkRefusal, LinkSession, LinkSessionId,
    LinkState, RelayLink, RelaySide,
};
use crate::foundation::process::{ProcessError, ProcessIdentity};

/// The pipe mode of the link: a byte stream (frames carry their own lengths), blocking
/// semantics under overlapped I/O, and no client through the network redirector.
pub const RELAY_PIPE_MODE: u32 =
    PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS;


/// The pipe's buffer in each direction.
const PIPE_BUFFER_BYTES: u32 = 64 * 1024;

/// The most bytes one read takes.
const READ_CHUNK_BYTES: usize = 64 * 1024;

/// How long the relay waits between attempts while the pipe's instance is busy.
const BUSY_RETRY: Duration = Duration::from_millis(10);

/// The name of a link's pipe in the local namespace: `\\.\pipe\` and 1 to 200 ASCII
/// letters, digits, `-`, `_` or `.`.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct RelayPipeName(String);

impl RelayPipeName {
    pub fn new(name: impl Into<String>) -> Result<Self, PipeError> {
        let name = name.into();
        let Some(rest) = name.strip_prefix(LOCAL_PIPE_PREFIX) else {
            return Err(PipeError::InvalidName);
        };
        let allowed = |c: char| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.');
        if rest.is_empty() || rest.len() > MAX_PIPE_NAME_CHARS || !rest.chars().all(allowed) {
            return Err(PipeError::InvalidName);
        }
        Ok(Self(name))
    }

    /// The pipe of one link session, unique to it.
    pub fn for_session(session: &LinkSessionId) -> Self {
        Self(format!(
            "{LOCAL_PIPE_PREFIX}yougori-relay-link-{}",
            session.digest().to_hex()
        ))
    }

    /// The link pipe of the relay process `relay`. A confined relay inherits nothing from
    /// the broker that starts it, so it finds its pipe by its own PX1 identity, which the
    /// broker reads when it starts it.
    pub fn for_relay(relay: &ProcessIdentity) -> Self {
        Self(format!(
            "{LOCAL_PIPE_PREFIX}yougori-relay-link-{}-{}",
            relay.pid, relay.start_time_ticks
        ))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub(super) fn wide(&self) -> Vec<u16> {
        self.0.encode_utf16().chain(Some(0)).collect()
    }
}

impl fmt::Display for RelayPipeName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

type ReadPeerPid = unsafe extern "system" fn(HANDLE, *mut u32) -> BOOL;

/// Reads the PID at the other end of `pipe` with `read` and judges it against
/// `registered`.
pub(super) fn admit(
    pipe: &OwnedHandle,
    registered: &ProcessIdentity,
    read: ReadPeerPid,
    call: PipeCall,
) -> Result<(), PipeError> {
    let mut pid = 0_u32;
    // SAFETY: the pipe handle is open and connected; `pid` is live.
    if unsafe { read(pipe.as_raw_handle(), &mut pid) } == 0 {
        return Err(host_error(call));
    }
    judge_peer(registered, pid, ProcessIdentity::check)
}

pub(super) fn is_disconnection(os_error: u32) -> bool {
    matches!(
        os_error,
        ERROR_BROKEN_PIPE | ERROR_PIPE_NOT_CONNECTED | ERROR_NO_DATA
    )
}

/// The time left until `deadline`; `None` is a deadline too far to represent, which no
/// wait reaches.
pub(super) fn left(deadline: Option<Instant>, within: Duration) -> Duration {
    deadline.map_or(within, |deadline| {
        deadline.saturating_duration_since(Instant::now())
    })
}

/// The broker's end of a link's pipe before a relay is admitted (see the module notes).
#[derive(Debug)]
pub struct RelayPipeListener {
    name: RelayPipeName,
    /// The pipe's one instance, until an admitted connection takes it.
    pipe: Option<OwnedHandle>,
    event: OwnedHandle,
}

impl RelayPipeListener {
    /// Creates the pipe's one instance, owner-only, rejecting remote clients. Refused if
    /// any instance of the name exists, so no other process holds it first.
    pub fn create(name: RelayPipeName) -> Result<Self, PipeError> {
        let mut security = OwnerOnly::current_user()?;
        let attributes = security.attributes();
        Self::create_with(name, &attributes)
    }

    /// Creates the pipe's one instance as [`RelayPipeListener::create`] does, for a relay
    /// confined in the AppContainer whose SID is `container` (its binary form): the
    /// protected DACL also grants that AppContainer [`CONTAINER_PIPE_ACCESS`], read and
    /// write and nothing else, and the pipe carries a low mandatory label with no write up,
    /// so the low-integrity relay may open it. Admission is unchanged: only the registered
    /// relay process, by PX1 identity. A `container` that is not one AppContainer SID
    /// (`S-1-15-2-...`) is refused.
    pub fn create_for_container(name: RelayPipeName, container: &[u8]) -> Result<Self, PipeError> {
        let mut security = OwnerAndContainer::new(container)?;
        let attributes = security.attributes();
        Self::create_with(name, &attributes)
    }

    /// Creates the pipe's one instance under `attributes`, refused if any instance of the
    /// name exists.
    fn create_with(
        name: RelayPipeName,
        attributes: &SECURITY_ATTRIBUTES,
    ) -> Result<Self, PipeError> {
        let wide = name.wide();
        // SAFETY: `wide` is a NUL-terminated name and `attributes` points into the
        // caller's security descriptor, both live for the call.
        let raw = unsafe {
            CreateNamedPipeW(
                wide.as_ptr(),
                PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE,
                RELAY_PIPE_MODE,
                1,
                PIPE_BUFFER_BYTES,
                PIPE_BUFFER_BYTES,
                0,
                attributes,
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

    /// Waits at most `within` for a client and admits it only if it is exactly
    /// `binding.relay`; the link session then opens on `binding` under `key`. A refused
    /// client is disconnected before a byte is read, and the listener may accept again.
    pub fn accept(
        &mut self,
        binding: LinkBinding,
        key: LinkKey,
        within: Duration,
    ) -> Result<LinkPipe<BrokerSide>, PipeError> {
        let pipe = self.pipe.as_ref().ok_or(PipeError::Spent)?;
        // SAFETY: the pipe handle is open; `complete` keeps `overlapped` live until the
        // operation ends.
        let connected = complete(pipe, &self.event, within, |raw, overlapped| unsafe {
            ConnectNamedPipe(raw, overlapped)
        });
        let refused = match connected {
            Ok(_) | Err(Incomplete::Failed(ERROR_PIPE_CONNECTED)) => admit(
                pipe,
                &binding.relay,
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
            self.disconnect();
            return Err(error);
        }
        let pipe = self.pipe.take().ok_or(PipeError::Spent)?;
        LinkPipe::new(pipe, binding.relay, BrokerLink::open(binding, key))
    }

    /// Admits the relay as [`RelayPipeListener::accept`] does, then writes `handoff` to it
    /// ahead of the link's first frame: its length as a big-endian `u32`, then its bytes,
    /// waiting at most `within` for each. So whatever the relay needs at start, its link
    /// key included, reaches only the process admitted by PX1 identity, over a pipe it
    /// opened itself, and no handle is ever inherited for it. A failure after admission
    /// ends the session: the handoff may be cut short.
    pub fn accept_with_handoff(
        &mut self,
        binding: LinkBinding,
        key: LinkKey,
        handoff: &[u8],
        within: Duration,
    ) -> Result<LinkPipe<BrokerSide>, PipeError> {
        let length = u32::try_from(handoff.len()).map_err(|_| {
            PipeError::Link(LinkRefusal::Oversize {
                declared: u64::try_from(handoff.len()).unwrap_or(u64::MAX),
                max: u64::from(u32::MAX),
            })
        })?;
        if length == 0 {
            return Err(PipeError::Link(LinkRefusal::EmptyBody));
        }
        let mut link = self.accept(binding, key, within)?;
        let written = write_all(&link.pipe, &link.event, &length.to_be_bytes(), within)
            .and_then(|()| write_all(&link.pipe, &link.event, handoff, within));
        if let Err(error) = written {
            link.session.fail(LinkRefusal::Interrupted);
            return Err(error);
        }
        Ok(link)
    }

    /// Drops the client at the other end. If that fails, the instance is closed instead,
    /// which drops the client too, and the listener is spent.
    fn disconnect(&mut self) {
        let dropped = self.pipe.as_ref().is_some_and(|pipe| {
            // SAFETY: the pipe handle is open.
            unsafe { DisconnectNamedPipe(pipe.as_raw_handle()) != 0 }
        });
        if !dropped {
            self.pipe = None;
        }
    }

    /// The pipe's instance, for tests that inspect it.
    #[cfg(test)]
    pub(super) fn raw_pipe(&self) -> Option<HANDLE> {
        self.pipe.as_ref().map(AsRawHandle::as_raw_handle)
    }
}

/// The relay's side: opens the pipe `name`, waiting at most `within` while its instance
/// is busy, admits the server only if it is exactly `broker`, and opens the relay's link
/// session on `binding` under `key`. The pipe is opened at identification level, so the
/// server can identify the relay but never act as it.
pub fn connect_relay(
    name: &RelayPipeName,
    binding: LinkBinding,
    key: LinkKey,
    broker: &ProcessIdentity,
    within: Duration,
) -> Result<LinkPipe<RelaySide>, PipeError> {
    let pipe = open_client(name, GENERIC_READ | GENERIC_WRITE, false, within)?;
    admit(
        &pipe,
        broker,
        GetNamedPipeServerProcessId,
        PipeCall::ServerProcess,
    )?;
    LinkPipe::new(pipe, *broker, RelayLink::open(binding, key))
}

/// A confined relay's end of its link pipe before the link opens (see
/// [`open_confined_relay`]): the pipe is open and its server admitted, the broker's
/// handoff not yet read.
#[derive(Debug)]
pub struct HandoverPipe {
    pipe: OwnedHandle,
    event: OwnedHandle,
    server: u32,
}

/// The side of a relay confined in an AppContainer (see
/// [`RelayPipeListener::create_for_container`]), which inherits nothing: opens the pipe
/// `name` asking only for [`CONTAINER_PIPE_ACCESS`], at identification level, waiting at
/// most `within` while the pipe does not exist yet or its instance is busy, and admits the
/// server only if its PID is `creator`'s, the process that started the relay.
///
/// A confined relay cannot open another process to read its creation time: its
/// AppContainer has no access to it. It needs none: its creator holds it in a kill-on-close
/// job (PX1), so while the relay runs the creator lives on and its PID names no other
/// process. The broker's admission of the relay is PX1's full check.
pub fn open_confined_relay(
    name: &RelayPipeName,
    creator: u32,
    within: Duration,
) -> Result<HandoverPipe, PipeError> {
    let pipe = open_client(name, CONTAINER_PIPE_ACCESS, true, within)?;
    let mut server = 0_u32;
    // SAFETY: the pipe handle is open and connected; `server` is live.
    if unsafe { GetNamedPipeServerProcessId(pipe.as_raw_handle(), &mut server) } == 0 {
        return Err(host_error(PipeCall::ServerProcess));
    }
    if server != creator {
        return Err(PipeError::Peer(PeerRefusal::OtherProcess { pid: server }));
    }
    Ok(HandoverPipe {
        pipe,
        event: new_event()?,
        server,
    })
}

impl HandoverPipe {
    /// The PID of the admitted server.
    pub fn server(&self) -> u32 {
        self.server
    }

    /// Reads the broker's handoff (see [`RelayPipeListener::accept_with_handoff`]): a
    /// big-endian `u32` length of 1 to `max` bytes, then exactly that many bytes, waiting
    /// at most `within` in all. A larger or empty declared length is refused before any of
    /// its bytes is read; nothing after the handoff is read.
    pub fn read_handoff(&mut self, max: usize, within: Duration) -> Result<Vec<u8>, PipeError> {
        let deadline = Instant::now().checked_add(within);
        let mut header = [0_u8; 4];
        read_exact(&self.pipe, &self.event, &mut header, deadline, within)?;
        let declared = u32::from_be_bytes(header);
        let length = usize::try_from(declared)
            .ok()
            .filter(|length| *length <= max)
            .ok_or(PipeError::Link(LinkRefusal::Oversize {
                declared: u64::from(declared),
                max: u64::try_from(max).unwrap_or(u64::MAX),
            }))?;
        if length == 0 {
            return Err(PipeError::Link(LinkRefusal::EmptyBody));
        }
        let mut handoff = vec![0_u8; length];
        read_exact(&self.pipe, &self.event, &mut handoff, deadline, within)?;
        Ok(handoff)
    }

    /// Opens the relay's link session on the pipe, bound to `binding` under `key`;
    /// `broker`, which the handoff names, must be the admitted server.
    pub fn into_link(
        self,
        binding: LinkBinding,
        key: LinkKey,
        broker: &ProcessIdentity,
    ) -> Result<LinkPipe<RelaySide>, PipeError> {
        if broker.pid != self.server {
            return Err(PipeError::Peer(PeerRefusal::OtherProcess {
                pid: self.server,
            }));
        }
        Ok(LinkPipe {
            pipe: self.pipe,
            event: self.event,
            peer: *broker,
            session: RelayLink::open(binding, key),
            decoder: FrameDecoder::new(),
            pending: Vec::new(),
        })
    }
}

/// Opens the client end of `name` with `access`, at identification level, waiting at most
/// `within` while the pipe's instance is busy, or, with `until_created`, while no pipe of
/// the name exists yet.
pub(super) fn open_client(
    name: &RelayPipeName,
    access: u32,
    until_created: bool,
    within: Duration,
) -> Result<OwnedHandle, PipeError> {
    let wide = name.wide();
    let deadline = Instant::now().checked_add(within);
    loop {
        // SAFETY: `wide` is a NUL-terminated name; no security attributes or template.
        let raw = unsafe {
            CreateFileW(
                wide.as_ptr(),
                access,
                0,
                null(),
                OPEN_EXISTING,
                FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
                null_mut(),
            )
        };
        if raw != INVALID_HANDLE_VALUE {
            return owned(raw).ok_or_else(|| host_error(PipeCall::OpenPipe));
        }
        let os_error = last_error();
        let waits =
            os_error == ERROR_PIPE_BUSY || (until_created && os_error == ERROR_FILE_NOT_FOUND);
        if !waits {
            return Err(PipeError::HostCall {
                call: PipeCall::OpenPipe,
                os_error,
            });
        }
        let remaining = left(deadline, within);
        if remaining.is_zero() {
            return Err(PipeError::TimedOut);
        }
        thread::sleep(BUSY_RETRY.min(remaining));
    }
}

/// One admitted end of a link's pipe (see the module notes).
#[derive(Debug)]
pub struct LinkPipe<E: LinkEnd> {
    pipe: OwnedHandle,
    event: OwnedHandle,
    peer: ProcessIdentity,
    session: LinkSession<E>,
    decoder: FrameDecoder,
    /// Bytes read and not yet taken by the decoder.
    pending: Vec<u8>,
}

impl<E: LinkEnd> LinkPipe<E> {
    fn new(
        pipe: OwnedHandle,
        peer: ProcessIdentity,
        session: LinkSession<E>,
    ) -> Result<Self, PipeError> {
        Ok(Self {
            pipe,
            event: new_event()?,
            peer,
            session,
            decoder: FrameDecoder::new(),
            pending: Vec::new(),
        })
    }

    /// The process at the other end, as admitted.
    pub fn peer(&self) -> ProcessIdentity {
        self.peer
    }

    pub fn session(&self) -> &LinkSession<E> {
        &self.session
    }

    /// Seals `message` and writes its frame, waiting at most `within`. A failure after
    /// sealing ends the session: the frame may be cut short.
    pub fn send(&mut self, message: E::Sends, within: Duration) -> Result<(), PipeError> {
        let bytes = self.session.seal(message)?;
        if let Err(error) = write_all(&self.pipe, &self.event, &bytes, within) {
            self.session.fail(LinkRefusal::Interrupted);
            return Err(error);
        }
        Ok(())
    }

    /// Reads until a whole frame is in, waiting at most `within`, and returns the message
    /// the session accepts from it. A timeout keeps what arrived for the next call.
    pub fn receive(&mut self, within: Duration) -> Result<E::Receives, PipeError> {
        match self.session.state() {
            LinkState::Open => {}
            LinkState::Closed { .. } => return Err(LinkRefusal::Closed.into()),
            LinkState::Failed(_) => return Err(LinkRefusal::Failed.into()),
        }
        let deadline = Instant::now().checked_add(within);
        let mut buffer = vec![0_u8; READ_CHUNK_BYTES];
        let length = u32::try_from(buffer.len()).unwrap_or(u32::MAX);
        loop {
            if let Some(frame) = self.decoder.take() {
                return Ok(self.session.accept(&frame)?);
            }
            if !self.pending.is_empty() {
                match self.decoder.feed(&self.pending) {
                    Ok(used) => {
                        self.pending.drain(..used);
                        continue;
                    }
                    Err(refusal) => {
                        self.session.fail(refusal.clone());
                        return Err(refusal.into());
                    }
                }
            }
            let remaining = left(deadline, within);
            if remaining.is_zero() {
                return Err(PipeError::TimedOut);
            }
            // SAFETY: `buffer` holds `length` writable bytes and outlives the operation,
            // which `complete` waits for.
            let result = complete(
                &self.pipe,
                &self.event,
                remaining,
                |raw, overlapped| unsafe {
                    ReadFile(raw, buffer.as_mut_ptr(), length, null_mut(), overlapped)
                },
            );
            let error = match result {
                Ok(0) => PipeError::Disconnected,
                Ok(count) => {
                    let count = usize::try_from(count).unwrap_or(0).min(buffer.len());
                    self.pending.extend_from_slice(&buffer[..count]);
                    continue;
                }
                Err(Incomplete::TimedOut) => return Err(PipeError::TimedOut),
                Err(Incomplete::Failed(os_error)) if is_disconnection(os_error) => {
                    PipeError::Disconnected
                }
                Err(Incomplete::Failed(os_error)) => PipeError::HostCall {
                    call: PipeCall::Read,
                    os_error,
                },
            };
            self.session.fail(LinkRefusal::Interrupted);
            return Err(error);
        }
    }
}

/// Writes all of `bytes` to `pipe`, waiting at most `within` in all.
pub(super) fn write_all(
    pipe: &OwnedHandle,
    event: &OwnedHandle,
    bytes: &[u8],
    within: Duration,
) -> Result<(), PipeError> {
    let deadline = Instant::now().checked_add(within);
    let mut written = 0_usize;
    while written < bytes.len() {
        let rest = &bytes[written..];
        let length = u32::try_from(rest.len()).unwrap_or(u32::MAX);
        // SAFETY: `rest` holds `length` readable bytes and outlives the operation, which
        // `complete` waits for.
        let result = complete(
            pipe,
            event,
            left(deadline, within),
            |raw, overlapped| unsafe {
                WriteFile(raw, rest.as_ptr(), length, null_mut(), overlapped)
            },
        );
        match result {
            Ok(0) => return Err(PipeError::Disconnected),
            Ok(count) => {
                written = written.saturating_add(usize::try_from(count).unwrap_or(usize::MAX));
            }
            Err(Incomplete::TimedOut) => return Err(PipeError::TimedOut),
            Err(Incomplete::Failed(os_error)) if is_disconnection(os_error) => {
                return Err(PipeError::Disconnected)
            }
            Err(Incomplete::Failed(os_error)) => {
                return Err(PipeError::HostCall {
                    call: PipeCall::Write,
                    os_error,
                })
            }
        }
    }
    Ok(())
}

/// Fills `buffer` from `pipe`, reading no byte beyond it, by `deadline` (`within` when it
/// is too far to represent).
pub(super) fn read_exact(
    pipe: &OwnedHandle,
    event: &OwnedHandle,
    buffer: &mut [u8],
    deadline: Option<Instant>,
    within: Duration,
) -> Result<(), PipeError> {
    let mut filled = 0_usize;
    while filled < buffer.len() {
        let remaining = left(deadline, within);
        if remaining.is_zero() {
            return Err(PipeError::TimedOut);
        }
        let rest = &mut buffer[filled..];
        let length = u32::try_from(rest.len()).unwrap_or(u32::MAX);
        // SAFETY: `rest` holds `length` writable bytes and outlives the operation, which
        // `complete` waits for.
        let result = complete(pipe, event, remaining, |raw, overlapped| unsafe {
            ReadFile(raw, rest.as_mut_ptr(), length, null_mut(), overlapped)
        });
        match result {
            Ok(0) => return Err(PipeError::Disconnected),
            Ok(count) => {
                filled = filled.saturating_add(usize::try_from(count).unwrap_or(usize::MAX));
            }
            Err(Incomplete::TimedOut) => return Err(PipeError::TimedOut),
            Err(Incomplete::Failed(os_error)) if is_disconnection(os_error) => {
                return Err(PipeError::Disconnected)
            }
            Err(Incomplete::Failed(os_error)) => {
                return Err(PipeError::HostCall {
                    call: PipeCall::Read,
                    os_error,
                })
            }
        }
    }
    Ok(())
}
