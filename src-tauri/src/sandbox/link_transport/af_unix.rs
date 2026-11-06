//! The link socket of a QEMU launch on Windows: an AF_UNIX stream socket that QEMU serves
//! in the launch's private directory (`-chardev socket,path=<dir>\link.sock,server=on`),
//! checked as a port before the host reads a byte from it (§3.2 lines 2061 and 2073–2074:
//! "Bind the host's channel to the VM object it launched"; VM-W06 line 2591; §7.3 lines
//! 2376–2386; tracker M06: "Restrict transport writers").
//!
//! The host is the client. It connects only to the link socket of the launch's
//! [`PrivateDirectory`], asks the connected stream which process serves it
//! ([`PeerProcess`]: Winsock's `SIO_AF_UNIX_GETPEERPID`), and admits the stream only when
//! that process is the QEMU process the host started: the peer's process id is the one
//! in the host's [`ProcessIdentity`] of it, and the process that holds that id now is
//! that identity, creation time included, so a process id reused by a later process is
//! not taken for it ([`ProcessTable`]). A stream whose peer is anything else is refused
//! and dropped unread ([`EndpointRefusal`]). Only a [`CheckedStream`] carries the link.
//!
//! No operating-system call is made here: the Winsock stream and its peer query, and the
//! process lookup, are the integration's (agent R1 supplies the AF_UNIX stream; the
//! lookup is `foundation::process::ProcessIdentity::holder_of`).

use std::fmt;
use std::io::{self, Read, Write};

use serde::Serialize;

use crate::foundation::process::{ProcessError, ProcessIdentity};
use crate::sandbox::qemu::{HostPath, PrivateDirectory};

use super::driver::FailureKind;
use super::stream_io::StreamShutdown;

/// The process at the other end of a connected stream, as the operating system recorded
/// it for the connection (Winsock `SIO_AF_UNIX_GETPEERPID`).
pub trait PeerProcess {
    /// The peer's process id. Called before any byte is read.
    fn peer_process_id(&self) -> io::Result<u32>;
}

/// Which process holds a process id now, as the host observes it through a handle (the
/// production port is `ProcessIdentity::holder_of`).
pub trait ProcessTable {
    fn holder_of(&self, pid: u32) -> Result<Option<ProcessIdentity>, ProcessError>;
}

/// Opens a stream to an AF_UNIX socket path (the integration's Winsock client).
pub trait LinkConnector {
    type Stream: Read + Write + PeerProcess;

    fn connect(&mut self, socket: &HostPath) -> io::Result<Self::Stream>;
}

/// Why a link stream was refused. A refused stream is dropped without a byte read.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "endpoint_refusal", rename_all = "snake_case")]
pub enum EndpointRefusal {
    /// The connection to the link socket failed.
    Connect {
        kind: FailureKind,
        os_error: Option<i32>,
    },
    /// The stream could not say which process serves it.
    PeerUnknown {
        kind: FailureKind,
        os_error: Option<i32>,
    },
    /// Another process than the QEMU process the host started serves the socket.
    WrongPeer { peer_pid: u32, vmm: ProcessIdentity },
    /// The peer has the QEMU process's id, but that id is held by no process or by
    /// another, later process now.
    NotTheVmm {
        vmm: ProcessIdentity,
        holder: Option<ProcessIdentity>,
    },
    /// The host could not look the process id up.
    Lookup { error: ProcessError },
}

impl EndpointRefusal {
    fn io(error: &io::Error, connect: bool) -> Self {
        let kind = FailureKind::of(error.kind());
        let os_error = error.raw_os_error();
        if connect {
            Self::Connect { kind, os_error }
        } else {
            Self::PeerUnknown { kind, os_error }
        }
    }
}

impl fmt::Display for EndpointRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Connect { kind, os_error } => {
                write!(f, "connecting to the link socket failed: {kind:?}")?;
                if let Some(code) = os_error {
                    write!(f, " (os error {code})")?;
                }
                Ok(())
            }
            Self::PeerUnknown { kind, os_error } => {
                write!(f, "the link stream's peer process is unknown: {kind:?}")?;
                if let Some(code) = os_error {
                    write!(f, " (os error {code})")?;
                }
                Ok(())
            }
            Self::WrongPeer { peer_pid, vmm } => write!(
                f,
                "the link socket is served by process {peer_pid}, not by the QEMU {vmm}"
            ),
            Self::NotTheVmm { vmm, holder } => match holder {
                Some(holder) => write!(f, "the QEMU {vmm} is gone; {holder} holds its id"),
                None => write!(f, "the QEMU {vmm} is gone"),
            },
            Self::Lookup { error } => write!(f, "the peer process could not be looked up: {error}"),
        }
    }
}

impl std::error::Error for EndpointRefusal {}

/// The link endpoint of one QEMU launch: the link socket in the launch's private
/// directory and the QEMU process the host started for it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct LinkSocketEndpoint {
    socket: HostPath,
    vmm: ProcessIdentity,
}

impl LinkSocketEndpoint {
    /// The endpoint of the launch whose private directory is `directory` and whose QEMU
    /// process the host started as `vmm`; the socket is the directory's `link.sock`.
    pub fn new(directory: &PrivateDirectory, vmm: ProcessIdentity) -> Self {
        Self {
            socket: directory.link_socket().clone(),
            vmm,
        }
    }

    /// The one path the host connects to.
    pub fn socket(&self) -> &HostPath {
        &self.socket
    }

    /// The QEMU process the peer must be.
    pub fn vmm(&self) -> ProcessIdentity {
        self.vmm
    }

    /// Connects to this launch's link socket through `connector` and admits the stream
    /// ([`LinkSocketEndpoint::admit`]).
    pub fn connect<K: LinkConnector>(
        &self,
        connector: &mut K,
        processes: &impl ProcessTable,
    ) -> Result<CheckedStream<K::Stream>, EndpointRefusal> {
        let stream = connector
            .connect(&self.socket)
            .map_err(|error| EndpointRefusal::io(&error, true))?;
        self.admit(stream, processes)
    }

    /// Admits a connected stream whose peer is the QEMU process the host started; any
    /// other stream is refused and dropped before a byte is read from it.
    pub fn admit<S: Read + Write + PeerProcess>(
        &self,
        stream: S,
        processes: &impl ProcessTable,
    ) -> Result<CheckedStream<S>, EndpointRefusal> {
        let peer_pid = stream
            .peer_process_id()
            .map_err(|error| EndpointRefusal::io(&error, false))?;
        if peer_pid != self.vmm.pid {
            return Err(EndpointRefusal::WrongPeer {
                peer_pid,
                vmm: self.vmm,
            });
        }
        match processes.holder_of(peer_pid) {
            Ok(Some(holder)) if holder == self.vmm => Ok(CheckedStream {
                stream,
                peer: holder,
            }),
            Ok(holder) => Err(EndpointRefusal::NotTheVmm {
                vmm: self.vmm,
                holder,
            }),
            Err(error) => Err(EndpointRefusal::Lookup { error }),
        }
    }
}

/// A link stream whose peer is the launch's QEMU process; nothing was read from it
/// before the check.
pub struct CheckedStream<S> {
    stream: S,
    peer: ProcessIdentity,
}

impl<S> CheckedStream<S> {
    /// The QEMU process the stream was checked against.
    pub fn peer(&self) -> ProcessIdentity {
        self.peer
    }

    pub fn get_ref(&self) -> &S {
        &self.stream
    }

    pub fn into_inner(self) -> S {
        self.stream
    }
}

impl<S> fmt::Debug for CheckedStream<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CheckedStream")
            .field("peer", &self.peer)
            .finish_non_exhaustive()
    }
}

impl<S: Read> Read for CheckedStream<S> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.stream.read(buffer)
    }
}

impl<S: Write> Write for CheckedStream<S> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.stream.write(bytes)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}

impl<S: StreamShutdown> StreamShutdown for CheckedStream<S> {
    fn shut_down(&mut self) -> io::Result<()> {
        self.stream.shut_down()
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::rc::Rc;

    use super::*;
    use crate::foundation::process::HostCall;
    use crate::sandbox::qemu::PathStyle;

    const QEMU: ProcessIdentity = ProcessIdentity {
        pid: 4_242,
        start_time_ticks: 133_000_000_000_000_000,
    };

    fn directory() -> PrivateDirectory {
        PrivateDirectory::new(HostPath::new(PathStyle::Windows, r"C:\Yougori\vm\a1b2c3").unwrap())
            .unwrap()
    }

    /// A connected stream that counts every read and write.
    struct Stream {
        peer: io::Result<u32>,
        reads: Rc<Cell<usize>>,
        writes: usize,
    }

    impl Stream {
        fn served_by(pid: u32) -> Self {
            Self {
                peer: Ok(pid),
                reads: Rc::default(),
                writes: 0,
            }
        }
    }

    impl PeerProcess for Stream {
        fn peer_process_id(&self) -> io::Result<u32> {
            match &self.peer {
                Ok(pid) => Ok(*pid),
                Err(error) => Err(io::Error::new(error.kind(), "no peer")),
            }
        }
    }

    impl Read for Stream {
        fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
            self.reads.set(self.reads.get() + 1);
            Ok(0)
        }
    }

    impl Write for Stream {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.writes += 1;
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl StreamShutdown for Stream {
        fn shut_down(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// The host's process table: `pid` held by `holder`.
    struct Table(Result<Option<ProcessIdentity>, ProcessError>);

    impl ProcessTable for Table {
        fn holder_of(&self, _pid: u32) -> Result<Option<ProcessIdentity>, ProcessError> {
            self.0.clone()
        }
    }

    struct Connector {
        dialed: Vec<String>,
        next: Option<io::Result<Stream>>,
    }

    impl LinkConnector for Connector {
        type Stream = Stream;

        fn connect(&mut self, socket: &HostPath) -> io::Result<Stream> {
            self.dialed.push(socket.as_str().to_owned());
            self.next
                .take()
                .unwrap_or_else(|| Err(io::Error::from(io::ErrorKind::NotFound)))
        }
    }

    #[test]
    fn the_endpoint_is_the_launchs_link_socket() {
        let endpoint = LinkSocketEndpoint::new(&directory(), QEMU);
        assert_eq!(
            endpoint.socket().as_str(),
            r"C:\Yougori\vm\a1b2c3\link.sock"
        );
        assert_eq!(endpoint.socket(), directory().link_socket());
        assert_eq!(endpoint.vmm(), QEMU);
        let mut connector = Connector {
            dialed: Vec::new(),
            next: Some(Ok(Stream::served_by(QEMU.pid))),
        };
        let checked = endpoint
            .connect(&mut connector, &Table(Ok(Some(QEMU))))
            .unwrap();
        assert_eq!(connector.dialed, vec![r"C:\Yougori\vm\a1b2c3\link.sock"]);
        assert_eq!(checked.peer(), QEMU);
        assert_eq!(
            checked.get_ref().reads.get(),
            0,
            "nothing read by the check"
        );
        assert!(format!("{checked:?}").contains("4242"));
    }

    #[test]
    fn a_stream_served_by_the_qemu_process_is_admitted_and_carries_bytes() {
        let endpoint = LinkSocketEndpoint::new(&directory(), QEMU);
        let mut checked = endpoint
            .admit(Stream::served_by(QEMU.pid), &Table(Ok(Some(QEMU))))
            .unwrap();
        assert_eq!(checked.write(b"frame").unwrap(), 5);
        checked.flush().unwrap();
        assert_eq!(checked.read(&mut [0u8; 4]).unwrap(), 0);
        checked.shut_down().unwrap();
        let stream = checked.into_inner();
        assert_eq!((stream.reads.get(), stream.writes), (1, 1));
    }

    #[test]
    fn a_stream_whose_peer_is_anything_else_is_refused_unread() {
        let endpoint = LinkSocketEndpoint::new(&directory(), QEMU);
        let reused = ProcessIdentity {
            pid: QEMU.pid,
            start_time_ticks: QEMU.start_time_ticks + 1,
        };
        let cases: Vec<(Stream, Table, EndpointRefusal)> = vec![
            (
                Stream::served_by(7),
                Table(Ok(Some(QEMU))),
                EndpointRefusal::WrongPeer {
                    peer_pid: 7,
                    vmm: QEMU,
                },
            ),
            (
                Stream::served_by(QEMU.pid),
                Table(Ok(Some(reused))),
                EndpointRefusal::NotTheVmm {
                    vmm: QEMU,
                    holder: Some(reused),
                },
            ),
            (
                Stream::served_by(QEMU.pid),
                Table(Ok(None)),
                EndpointRefusal::NotTheVmm {
                    vmm: QEMU,
                    holder: None,
                },
            ),
            (
                Stream::served_by(QEMU.pid),
                Table(Err(ProcessError::HostCall {
                    call: HostCall::OpenProcess,
                    os_error: 5,
                })),
                EndpointRefusal::Lookup {
                    error: ProcessError::HostCall {
                        call: HostCall::OpenProcess,
                        os_error: 5,
                    },
                },
            ),
            (
                Stream {
                    peer: Err(io::Error::from(io::ErrorKind::Unsupported)),
                    reads: Rc::default(),
                    writes: 0,
                },
                Table(Ok(Some(QEMU))),
                EndpointRefusal::PeerUnknown {
                    kind: FailureKind::Other,
                    os_error: None,
                },
            ),
        ];
        for (stream, table, expected) in cases {
            let reads = Rc::clone(&stream.reads);
            let refused = endpoint.admit(stream, &table).unwrap_err();
            assert_eq!(refused, expected);
            assert_eq!(reads.get(), 0, "{refused}");
            assert!(!refused.to_string().is_empty());
            assert!(serde_json::to_value(&refused).is_ok());
        }
    }

    #[test]
    fn a_failed_connection_is_typed_and_nothing_else_is_dialed() {
        let endpoint = LinkSocketEndpoint::new(&directory(), QEMU);
        let mut connector = Connector {
            dialed: Vec::new(),
            next: Some(Err(io::Error::from(io::ErrorKind::ConnectionRefused))),
        };
        let refused = endpoint
            .connect(&mut connector, &Table(Ok(Some(QEMU))))
            .unwrap_err();
        assert_eq!(
            refused,
            EndpointRefusal::Connect {
                kind: FailureKind::Other,
                os_error: None
            }
        );
        assert_eq!(connector.dialed.len(), 1);
        assert!(refused.to_string().contains("connecting"));
    }
}
