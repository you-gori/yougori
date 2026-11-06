//! The control pipe between the engine and its sandbox executor process (M09/M11's process
//! separation: the executor holds the vault and brokers every relay; the engine holds
//! neither; docs/combined-gpu-memory-and-vm-sandbox-plan.md, VM part §3.1 and line 2763).
//! An owner-only named pipe the engine creates first under a per-run name, rejecting
//! remote clients, on which the engine admits only the executor process it started (PX1
//! identity) and the executor admits only the engine that named itself (PX1 identity,
//! read through the pipe's server PID). Lines of text move over it; what they say is the
//! executor protocol's. No credential or guest byte crosses it.

use std::fmt;
use std::os::windows::io::{AsRawHandle, OwnedHandle};
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{
    ERROR_NO_DATA, ERROR_PIPE_CONNECTED, GENERIC_READ, GENERIC_WRITE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Storage::FileSystem::{
    ReadFile, FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED, PIPE_ACCESS_DUPLEX,
};
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, GetNamedPipeClientProcessId,
    GetNamedPipeServerProcessId, PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE,
    PIPE_WAIT,
};

use super::pipe::{
    admit, is_disconnection, left, open_client, write_all, PipeCall, PipeError, RelayPipeName,
};
use super::pipe_os::{complete, host_error, new_event, owned, Incomplete, OwnerOnly};
use crate::foundation::process::ProcessIdentity;

const PIPE_BUFFER_BYTES: u32 = 64 * 1024;
const READ_CHUNK_BYTES: usize = 16 * 1024;

/// The longest line either end keeps before it refuses the peer.
pub const MAX_CONTROL_LINE_BYTES: usize = 256 * 1024;

/// The engine's end before the executor connected.
#[derive(Debug)]
pub struct ControlListener {
    name: RelayPipeName,
    pipe: Option<OwnedHandle>,
    event: OwnedHandle,
}

impl ControlListener {
    /// Creates the pipe's one instance, owner-only, remote clients rejected, refused if any
    /// instance of the name exists.
    pub fn create(name: RelayPipeName) -> Result<Self, PipeError> {
        let mut security = OwnerOnly::current_user()?;
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

    /// Waits at most `within` for a client and admits it only if it is exactly `executor`
    /// (PX1 identity); another client is disconnected and the listener may accept again.
    pub fn accept(
        &mut self,
        executor: &ProcessIdentity,
        within: Duration,
    ) -> Result<ControlPipe, PipeError> {
        let pipe = self.pipe.as_ref().ok_or(PipeError::Spent)?;
        // SAFETY: the pipe handle is open; `complete` keeps `overlapped` live until the
        // operation ends.
        let connected = complete(pipe, &self.event, within, |raw, overlapped| unsafe {
            ConnectNamedPipe(raw, overlapped)
        });
        let refused = match connected {
            Ok(_) | Err(Incomplete::Failed(ERROR_PIPE_CONNECTED)) => admit(
                pipe,
                executor,
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
            // SAFETY: the pipe handle is open; the refused client is disconnected.
            unsafe { DisconnectNamedPipe(pipe.as_raw_handle()) };
            return Err(error);
        }
        let pipe = self.pipe.take().ok_or(PipeError::Spent)?;
        Ok(ControlPipe {
            pipe,
            event: new_event()?,
            peer: *executor,
            pending: Vec::new(),
        })
    }
}

/// One admitted end of the control pipe: lines in, lines out.
pub struct ControlPipe {
    pipe: OwnedHandle,
    event: OwnedHandle,
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
    /// The executor's side: opens the pipe `name`, waiting at most `within` while it does
    /// not exist yet or is busy, and admits the server only if it is exactly `engine` (PX1
    /// identity through the pipe's server PID).
    pub fn connect(
        name: &RelayPipeName,
        engine: &ProcessIdentity,
        within: Duration,
    ) -> Result<Self, PipeError> {
        let pipe = open_client(name, GENERIC_READ | GENERIC_WRITE, true, within)?;
        admit(
            &pipe,
            engine,
            GetNamedPipeServerProcessId,
            PipeCall::ServerProcess,
        )?;
        Ok(Self {
            pipe,
            event: new_event()?,
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
        write_all(&self.pipe, &self.event, line, within)
    }

    /// The next line without its newline, within `within`; `None` when none completed in
    /// time. A line over the bound or a closed pipe is an error.
    pub fn read_line(&mut self, within: Duration) -> Result<Option<Vec<u8>>, PipeError> {
        let deadline = Instant::now().checked_add(within);
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
            let remaining = left(deadline, within);
            if remaining.is_zero() {
                return Ok(None);
            }
            let mut buffer = vec![0_u8; READ_CHUNK_BYTES];
            let length = u32::try_from(buffer.len()).unwrap_or(u32::MAX);
            // SAFETY: `buffer` holds `length` writable bytes and outlives the operation,
            // which `complete` waits for.
            let result = complete(&self.pipe, &self.event, remaining, |raw, overlapped| unsafe {
                ReadFile(raw, buffer.as_mut_ptr(), length, std::ptr::null_mut(), overlapped)
            });
            match result {
                Ok(0) => return Err(PipeError::Disconnected),
                Ok(count) => {
                    let count = usize::try_from(count).unwrap_or(0).min(buffer.len());
                    self.pending.extend_from_slice(&buffer[..count]);
                }
                Err(Incomplete::TimedOut) => return Ok(None),
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
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Two ends in this process: the listener admits this process, lines go both ways, a
    /// closed end is an error on the other.
    #[test]
    fn a_control_pipe_carries_lines_between_admitted_ends() {
        let me = ProcessIdentity::holder_of(std::process::id())
            .unwrap()
            .unwrap();
        let name = RelayPipeName::new(format!(
            r"\\.\pipe\yougori-control-test-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4().simple()
        ))
        .unwrap();
        let mut listener = ControlListener::create(name.clone()).unwrap();
        let client_name = name.clone();
        let client = std::thread::spawn(move || {
            let mut pipe = ControlPipe::connect(&client_name, &me, Duration::from_secs(5)).unwrap();
            pipe.send_line(b"hello from the executor\n", Duration::from_secs(5))
                .unwrap();
            let line = pipe.read_line(Duration::from_secs(5)).unwrap().unwrap();
            assert_eq!(line, b"hello from the engine");
            // Nothing within a short wait is `None`, not an error.
            assert!(pipe.read_line(Duration::from_millis(20)).unwrap().is_none());
            pipe.send_line(b"bye\n", Duration::from_secs(5)).unwrap();
        });
        let mut server = listener.accept(&me, Duration::from_secs(5)).unwrap();
        assert_eq!(server.peer(), me);
        let line = server.read_line(Duration::from_secs(5)).unwrap().unwrap();
        assert_eq!(line, b"hello from the executor");
        server
            .send_line(b"hello from the engine\n", Duration::from_secs(5))
            .unwrap();
        let line = server.read_line(Duration::from_secs(5)).unwrap().unwrap();
        assert_eq!(line, b"bye");
        client.join().unwrap();
        // The client end is gone: the next read says so.
        assert!(matches!(
            server.read_line(Duration::from_secs(2)),
            Err(PipeError::Disconnected)
        ));
    }
}
