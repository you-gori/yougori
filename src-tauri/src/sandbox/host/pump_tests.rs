//! The session pump and the terminal command path end to end (VM part §3.2 lines
//! 2059–2077; VM-W06 line 2591; §6.1–§6.3 lines 2284–2316; VM-P28 and VM-P29 lines
//! 2803–2804; VM-W24): the real host over the fake backend, one boot's link carried over
//! an in-memory byte stream by a [`SessionPump`], and a guest end built from the link's
//! own encoder that answers the challenge, says hello and runs commands as the Go guest
//! does (`Opened` and credit, then output and `Exit`).

use std::cell::RefCell;
use std::collections::VecDeque;
use std::io::{self, ErrorKind, Read, Write};
use std::rc::Rc;
use std::time::Duration;

use super::fakes::*;
use super::{
    ClosureCause, CommandEnd, CommandEvent, CommandRefusal, CommandRequest, CommandResult,
    Delivery, HostError, IngressEndCause, IngressEvent, IngressRefusal, PumpEvent, PumpRefusal,
    SessionPump, TransportState, MAX_COMMAND_INPUT_BYTES,
};
use crate::foundation::coordination::SandboxState;
use crate::foundation::evidence::SourceClass;
use crate::foundation::process::{ProcessError, ProcessIdentity};
use crate::sandbox::lifecycle::{Acknowledgment, RevocationCause, SandboxClass};
use crate::sandbox::link::{
    encode_frame_on, CancelCause, Channel, CloseCause, CloseReason, ConnectionNonce, GuestRequest,
    Hello, LinkBinding, LinkEvent, LinkLimits, LinkMessage, LinkName, OpenRefusalCause, Refusal,
    RefusalEffect, RefusalReason, ReportBody, Sender, StreamOpen, PROTOCOL_VERSION,
};
use crate::sandbox::link_transport::{
    CheckedStream, DriverLimits, DriverPhase, EndpointRefusal, FailureKind, LinkSocketEndpoint,
    PeerProcess, ProcessTable, StreamShutdown, TransportEnd, TransportEvent, TransportFailure,
    TransportOperation,
};
use crate::sandbox::qemu::{HostPath, PathStyle, PrivateDirectory};

const NAME: &str = "exe-task";

/// The QEMU process the host started for the boot.
const QEMU: ProcessIdentity = ProcessIdentity {
    pid: 5_150,
    start_time_ticks: 133_100_000_000_000_000,
};

/// Both directions of one in-memory stream.
#[derive(Default)]
struct WireState {
    /// What the guest wrote and the host has not read.
    to_host: VecDeque<u8>,
    /// What the host wrote and the guest has not read.
    to_guest: Vec<u8>,
    /// The guest ended its direction: once `to_host` is empty, a read returns no bytes.
    guest_ended: bool,
    read_error: Option<ErrorKind>,
    reads: usize,
    shut_downs: usize,
    peer_pid: u32,
    /// The stream takes no bytes for now (a full socket buffer).
    write_blocked: bool,
}

/// The host's end of the stream.
struct Wire(Rc<RefCell<WireState>>);

impl Wire {
    fn served_by(pid: u32) -> (Self, Rc<RefCell<WireState>>) {
        let state = Rc::new(RefCell::new(WireState {
            peer_pid: pid,
            ..WireState::default()
        }));
        (Self(Rc::clone(&state)), state)
    }
}

impl Read for Wire {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let mut state = self.0.borrow_mut();
        state.reads += 1;
        if let Some(kind) = state.read_error {
            return Err(io::Error::from(kind));
        }
        if state.to_host.is_empty() {
            return if state.guest_ended {
                Ok(0)
            } else {
                Err(io::Error::from(ErrorKind::WouldBlock))
            };
        }
        let count = buffer.len().min(state.to_host.len());
        for (slot, byte) in buffer.iter_mut().zip(state.to_host.drain(..count)) {
            *slot = byte;
        }
        Ok(count)
    }
}

impl Write for Wire {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let mut state = self.0.borrow_mut();
        if state.shut_downs > 0 {
            return Err(io::Error::from(ErrorKind::BrokenPipe));
        }
        if state.write_blocked {
            return Err(io::Error::from(ErrorKind::WouldBlock));
        }
        state.to_guest.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl StreamShutdown for Wire {
    fn shut_down(&mut self) -> io::Result<()> {
        self.0.borrow_mut().shut_downs += 1;
        Ok(())
    }
}

impl PeerProcess for Wire {
    fn peer_process_id(&self) -> io::Result<u32> {
        Ok(self.0.borrow().peer_pid)
    }
}

/// The launch's link socket endpoint.
fn endpoint() -> LinkSocketEndpoint {
    let directory = PrivateDirectory::new(
        HostPath::new(PathStyle::Windows, r"C:\Yougori\vm\exe-task").unwrap(),
    )
    .unwrap();
    LinkSocketEndpoint::new(&directory, QEMU)
}

/// `wire` admitted by the endpoint: its peer is the QEMU process.
fn checked(wire: Wire) -> CheckedStream<Wire> {
    endpoint().admit(wire, &Processes).unwrap()
}

/// The host's process table: the QEMU process holds its id.
struct Processes;

impl ProcessTable for Processes {
    fn holder_of(&self, pid: u32) -> Result<Option<ProcessIdentity>, ProcessError> {
        Ok((pid == QEMU.pid).then_some(QEMU))
    }
}

/// The guest end of the stream: the link's own encoder and the guest's key.
struct Guest {
    end: GuestEnd,
    wire: Rc<RefCell<WireState>>,
}

impl Guest {
    fn on(world: &World, wire: &Rc<RefCell<WireState>>) -> Self {
        Self {
            end: GuestEnd::new(world.vm(NAME), world.boot(NAME), secret(NAME)),
            wire: Rc::clone(wire),
        }
    }

    /// Everything the host wrote since the last read.
    fn read(&mut self) -> Vec<LinkMessage> {
        let bytes = std::mem::take(&mut self.wire.borrow_mut().to_guest);
        self.end.read(&[bytes])
    }

    fn sealed(&mut self, message: &LinkMessage) -> Vec<u8> {
        self.end.frame(message)
    }

    fn send(&mut self, message: &LinkMessage) {
        let frame = self.sealed(message);
        self.wire.borrow_mut().to_host.extend(frame);
    }

    fn hello() -> LinkMessage {
        LinkMessage::Hello(Hello {
            guest_version: PROTOCOL_VERSION,
            agent_build: named("yougori/test/agent/v1", "agent"),
            claimed_vm: None,
            claimed_boot: None,
        })
    }

    /// Accepts the host's terminal open and grants `credit` bytes of input.
    fn accept(&mut self, stream: u32, credit: u32) {
        self.send(&LinkMessage::Opened {
            channel: Channel::Terminal,
            stream: super::fakes::stream(stream),
        });
        self.send(&LinkMessage::WindowUpdate {
            channel: Channel::Terminal,
            credit_bytes: credit,
        });
    }

    fn output(&mut self, stream: u32, bytes: &[u8]) {
        self.send(&LinkMessage::Data {
            channel: Channel::Terminal,
            stream: super::fakes::stream(stream),
            bytes: bytes.to_vec(),
        });
    }
}

fn deliveries(events: &[PumpEvent]) -> Vec<&Delivery> {
    events
        .iter()
        .filter_map(|event| match event {
            PumpEvent::Delivered(delivery) => Some(delivery),
            _ => None,
        })
        .collect()
}

fn commands(events: &[PumpEvent]) -> Vec<CommandEvent> {
    deliveries(events)
        .into_iter()
        .flat_map(|delivery| delivery.commands.clone())
        .collect()
}

fn ended(events: &[PumpEvent]) -> Vec<CommandResult> {
    commands(events)
        .into_iter()
        .filter_map(|event| match event {
            CommandEvent::Ended(result) => Some(*result),
            _ => None,
        })
        .collect()
}

fn request(input: &[u8], max_output_bytes: usize) -> CommandRequest {
    CommandRequest {
        image_entrypoint: false,
        input: input.to_vec(),
        max_output_bytes,
        time_limit: 30 * SECOND,
        columns: 80,
        rows: 24,
    }
}

/// A launched boot whose channels are open, a pump over a fresh stream, and the guest at
/// the other end after the challenge, its hello and the welcome.
fn booted() -> (World, SessionPump<Wire>, Guest) {
    let mut world = World::new();
    world.launch(NAME, SandboxClass::Task);
    let setup = world.setup(NAME);
    world
        .host_mut()
        .open_channels(&execution(NAME), setup)
        .unwrap();
    let (wire, state) = Wire::served_by(QEMU.pid);
    let mut pump = SessionPump::new(
        world.host_mut(),
        execution(NAME),
        checked(wire),
        DriverLimits::default(),
    )
    .unwrap();
    assert_eq!(
        world.host().session(&execution(NAME)).unwrap().transport(),
        TransportState::Attached
    );
    let mut guest = Guest::on(&world, &state);
    handshake(&mut world, &mut pump, &mut guest, Some(1));
    (world, pump, guest)
}

/// The challenge of connection `number` (of any connection for `None`), the guest's hello
/// and the host's welcome, all over the pump.
fn handshake(
    world: &mut World,
    pump: &mut SessionPump<Wire>,
    guest: &mut Guest,
    number: Option<u32>,
) {
    assert_eq!(pump.step(world.host_mut()), vec![]);
    match &guest.read()[..] {
        [LinkMessage::Challenge { connection }] => {
            if let Some(number) = number {
                assert_eq!(*connection, connection_nonce(NAME, number).connection());
            }
            assert_eq!(guest.end.connection(), *connection);
        }
        other => panic!("the host's first frame is {other:?}"),
    }
    guest.send(&Guest::hello());
    let events = pump.step(world.host_mut());
    let delivered = deliveries(&events);
    assert_eq!(delivered.len(), 1, "{events:?}");
    assert_eq!(delivered[0].reports.len(), 1);
    assert_eq!(delivered[0].reports[0].source(), SourceClass::GuestReport);
    assert!(matches!(
        &guest.read()[..],
        [LinkMessage::Welcome(terms)] if terms.version == PROTOCOL_VERSION
            && terms.max_frame_bytes == 65_552
    ));
    assert!(world
        .host()
        .session(&execution(NAME))
        .unwrap()
        .link_is_open());
}

/// The whole path: the challenge, the hello and the welcome over the pump, then one
/// command: the terminal open, the guest's acceptance and credit, the input and its end,
/// the guest's output and exit report, and the terminal window credited back. The output
/// and the exit code are the guest's word.
#[test]
fn a_boot_runs_a_command_over_the_stream_from_challenge_to_exit_code() {
    let (mut world, mut pump, mut guest) = booted();
    let exe = execution(NAME);

    let stream = world
        .host_mut()
        .start_command(&exe, request(b"echo hi\n", 1_024))
        .unwrap();
    assert_eq!(stream.get(), 2);
    assert_eq!(pump.flush(world.host_mut()), vec![]);
    assert_eq!(
        guest.read(),
        vec![LinkMessage::Open {
            stream,
            open: StreamOpen::Terminal {
                columns: 80,
                rows: 24
            }
        }]
    );

    guest.accept(2, 4_096);
    let events = pump.step(world.host_mut());
    assert_eq!(
        commands(&events),
        vec![
            CommandEvent::Opened { stream },
            CommandEvent::InputEnded {
                stream,
                input_bytes: 8
            },
        ]
    );
    assert_eq!(
        guest.read(),
        vec![
            LinkMessage::Data {
                channel: Channel::Terminal,
                stream,
                bytes: b"echo hi\n".to_vec()
            },
            LinkMessage::EndOfStream {
                channel: Channel::Terminal,
                stream
            },
        ]
    );

    guest.output(2, b"hi\n");
    guest.send(&LinkMessage::Exit { stream, code: 0 });
    let events = pump.step(world.host_mut());
    let results = ended(&events);
    assert_eq!(results.len(), 1, "{events:?}");
    let result = &results[0];
    assert_eq!(result.stream, stream);
    assert_eq!(result.exit_code(), Some(0));
    assert_eq!(result.output.bytes(), b"hi\n");
    assert_eq!(result.output.dropped_bytes(), 0);
    assert_eq!(result.output.source(), SourceClass::GuestReport);
    assert_eq!(result.input_sent_bytes, 8);
    assert_eq!(result.unsent, None);
    match &result.end {
        CommandEnd::Exited { exit } => {
            assert_eq!(exit.source(), SourceClass::GuestReport);
            assert!(!exit.satisfies(SourceClass::HostProbe));
            assert_eq!(exit.vm(), world.vm(NAME));
            assert!(matches!(
                exit.body(),
                ReportBody::TerminalExit { code: 0, .. }
            ));
        }
        other => panic!("{other:?}"),
    }
    // The three output bytes are credited back to the guest.
    assert_eq!(
        guest.read(),
        vec![LinkMessage::WindowUpdate {
            channel: Channel::Terminal,
            credit_bytes: 3
        }]
    );
    let session = world.host().session(&exe).unwrap();
    assert_eq!(session.running_commands(), 0);
    assert_eq!(
        session.link().unwrap().channel(Channel::Terminal).streams,
        0
    );
    assert!(!pump.is_finished());
    assert_eq!(pump.counters().frames_written, 6);
    assert_eq!(
        world.host_mut().first_command(&exe),
        Ok(Duration::ZERO),
        "the caller marks the first command; the host does not take the guest's exit as it"
    );
}

/// Output beyond the caller's limit is counted and dropped, the stream is cancelled, and
/// the guest's later output on it is refused by the link without a command event.
#[test]
fn output_over_the_limit_is_counted_dropped_and_the_stream_cancelled() {
    let (mut world, mut pump, mut guest) = booted();
    let exe = execution(NAME);
    let stream = world
        .host_mut()
        .start_command(&exe, request(b"", 4))
        .unwrap();
    pump.flush(world.host_mut());
    guest.read();
    guest.accept(2, 1_024);
    pump.step(world.host_mut());
    assert_eq!(
        guest.read(),
        vec![LinkMessage::EndOfStream {
            channel: Channel::Terminal,
            stream
        }]
    );

    guest.output(2, b"abcdef");
    let events = pump.step(world.host_mut());
    let results = ended(&events);
    assert_eq!(results.len(), 1, "{events:?}");
    assert_eq!(results[0].end, CommandEnd::OutputLimitReached);
    assert_eq!(results[0].output.bytes(), b"abcd");
    assert_eq!(results[0].output.dropped_bytes(), 2);
    assert_eq!(results[0].exit_code(), None);
    let messages = guest.read();
    assert!(messages.contains(&LinkMessage::Cancel {
        channel: Channel::Terminal,
        stream,
        cause: CancelCause::QuotaExceeded
    }));
    assert!(messages.contains(&LinkMessage::WindowUpdate {
        channel: Channel::Terminal,
        credit_bytes: 6
    }));

    guest.output(2, b"more");
    guest.send(&LinkMessage::Exit { stream, code: 0 });
    let events = pump.step(world.host_mut());
    assert_eq!(commands(&events), vec![]);
    let refused: Vec<&LinkEvent> = deliveries(&events)
        .into_iter()
        .flat_map(|delivery| delivery.other.iter())
        .collect();
    assert_eq!(refused.len(), 2, "{refused:?}");
    assert!(refused.iter().all(|event| matches!(
        event,
        LinkEvent::Refused(Refusal {
            reason: RefusalReason::StreamCancelled { .. },
            effect: RefusalEffect::FrameDropped
        })
    )));
    assert!(world.host().session(&exe).unwrap().link_is_open());
}

/// The caller's cancel and the caller's time limit each cancel the stream on the link;
/// the command ends with the output so far.
#[test]
fn cancel_and_the_time_limit_cancel_the_stream() {
    let (mut world, mut pump, mut guest) = booted();
    let exe = execution(NAME);
    let first = world
        .host_mut()
        .start_command(&exe, request(b"sleep 100\n", 64))
        .unwrap();
    let second = world
        .host_mut()
        .start_command(
            &exe,
            CommandRequest {
                time_limit: 5 * SECOND,
                ..request(b"sleep 100\n", 64)
            },
        )
        .unwrap();
    assert_eq!((first.get(), second.get()), (2, 4));
    pump.flush(world.host_mut());
    guest.read();
    // Credit is per channel: exactly the first command's input.
    guest.accept(2, 10);
    guest.accept(4, 0);
    guest.output(2, b"partial");
    pump.step(world.host_mut());
    guest.read();

    let cancelled = world.host_mut().cancel_command(&exe, first).unwrap();
    assert_eq!(cancelled.end, CommandEnd::Cancelled);
    assert_eq!(cancelled.output.bytes(), b"partial");
    assert_eq!(cancelled.input_sent_bytes, 10);
    assert_eq!(
        world.host_mut().cancel_command(&exe, first),
        Err(HostError::Command(CommandRefusal::UnknownCommand {
            stream: first
        }))
    );
    pump.flush(world.host_mut());
    assert_eq!(
        guest.read(),
        vec![LinkMessage::Cancel {
            channel: Channel::Terminal,
            stream: first,
            cause: CancelCause::Requested
        }]
    );

    // Five seconds is still within the limit; past it, the next tick cancels the stream.
    world.advance(5 * SECOND);
    let tick = world.host_mut().tick().unwrap();
    assert!(tick
        .deliveries
        .iter()
        .all(|(_, delivery)| delivery.commands.is_empty()));
    world.advance(SECOND);
    let tick = world.host_mut().tick().unwrap();
    let results: Vec<&CommandResult> = tick
        .deliveries
        .iter()
        .flat_map(|(_, delivery)| delivery.commands.iter())
        .filter_map(|event| match event {
            CommandEvent::Ended(result) => Some(result.as_ref()),
            _ => None,
        })
        .collect();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].stream, second);
    assert_eq!(results[0].end, CommandEnd::TimeLimitPassed);
    assert_eq!(
        results[0].input_sent_bytes, 0,
        "the guest never granted credit"
    );
    pump.flush(world.host_mut());
    assert_eq!(
        guest.read(),
        vec![LinkMessage::Cancel {
            channel: Channel::Terminal,
            stream: second,
            cause: CancelCause::TimedOut
        }]
    );
    assert_eq!(world.host().session(&exe).unwrap().running_commands(), 0);
}

/// A revocation during a command: the host closes the boot's channels at once, the
/// command ends with the typed revoked result and the output so far, the pump writes the
/// close frame and shuts the stream, no further guest byte is taken, and only then, on the
/// stream's end the pump reports, is "channels closed" acknowledged: the host's session
/// state alone never stands for the physical closure.
#[test]
fn a_revocation_during_a_command_ends_it_revoked_and_takes_no_further_byte() {
    let (mut world, mut pump, mut guest) = booted();
    let exe = execution(NAME);
    let stream = world
        .host_mut()
        .start_command(&exe, request(b"yes\n", 1_024))
        .unwrap();
    pump.flush(world.host_mut());
    guest.read();
    guest.accept(2, 1_024);
    guest.output(2, b"y\ny\n");
    pump.step(world.host_mut());
    guest.read();
    world.host_mut().take_log();

    let progress = world
        .host_mut()
        .revoke(&exe, RevocationCause::UserRequested)
        .unwrap();
    // The channels are closed in the host, but the stream the pump carries has not ended:
    // the physical closure is not acknowledged from the session state.
    assert!(!progress
        .acknowledged
        .contains(&Acknowledgment::ChannelsClosed));
    assert!(!progress.acknowledged.contains(&Acknowledgment::VmStopped));
    let log = world.host_mut().take_log();
    let closure = log.closure_of(&exe).unwrap();
    assert_eq!(closure.cause, ClosureCause::Revoked);
    assert_eq!(closure.commands.len(), 1);
    let result = &closure.commands[0];
    assert_eq!(result.stream, stream);
    assert!(result.is_revoked());
    assert_eq!(
        result.end,
        CommandEnd::HostClosed {
            cause: ClosureCause::Revoked
        }
    );
    assert_eq!(result.output.bytes(), b"y\ny\n");
    assert!(log.acknowledgments.is_empty(), "{:?}", log.acknowledgments);
    assert_eq!(
        world.host().session(&exe).unwrap().transport(),
        TransportState::Attached
    );
    assert_ne!(world.state(NAME), SandboxState::Stopped);

    // The guest keeps writing; the pump reads nothing more, writes the close frame and
    // shuts the stream down.
    guest.output(2, b"y\ny\n");
    let reads_before = guest.wire.borrow().reads;
    let events = pump.step(world.host_mut());
    assert_eq!(
        events,
        vec![
            PumpEvent::ShutDown { failure: None },
            PumpEvent::Transport(TransportEvent::Finished {
                end: TransportEnd::LinkClosed
            }),
        ]
    );
    assert_eq!(guest.wire.borrow().reads, reads_before);
    assert_eq!(guest.wire.borrow().shut_downs, 1);
    assert!(!guest.wire.borrow().to_host.is_empty(), "left unread");
    assert_eq!(
        guest.read(),
        vec![LinkMessage::Close {
            reason: CloseReason::Revoked
        }]
    );
    // The stream ended: now the host acknowledges the channels closed, on that end, and
    // the revocation goes on to stop the VM.
    assert_eq!(
        world.host().session(&exe).unwrap().transport(),
        TransportState::Ended(TransportEnd::LinkClosed)
    );
    let log = world.host_mut().take_log();
    assert_eq!(log.acknowledgments.len(), 1, "{:?}", log.acknowledgments);
    assert_eq!(log.acknowledgments[0].execution, exe);
    assert_eq!(
        log.acknowledgments[0].transport_end,
        Some(TransportEnd::LinkClosed)
    );
    assert!(log.acknowledgments[0].outcome.is_ok());
    let run = world.host().supervisor().revocation(&exe).unwrap();
    assert!(run
        .acknowledged_at(Acknowledgment::ChannelsClosed)
        .is_some());
    assert_eq!(world.state(NAME), SandboxState::Stopped);
    assert_eq!(
        close_reason(&guest.end.read(&closure.final_frames)),
        Some(CloseReason::Revoked),
        "the closure records the same close frame"
    );
    let unread: Vec<u8> = guest.wire.borrow_mut().to_host.drain(..).collect();
    assert_eq!(
        world.host_mut().receive(&exe, &unread),
        Err(HostError::ChannelsClosed {
            execution: exe.clone(),
            boot: world.boot(NAME)
        })
    );
    assert_eq!(
        world.host_mut().start_command(&exe, request(b"", 1)),
        Err(HostError::ChannelsClosed {
            execution: exe.clone(),
            boot: world.boot(NAME)
        })
    );
    assert_eq!(pump.step(world.host_mut()), vec![]);
}

/// The stream ending in the middle of a command reaches the host as the peer gone: the
/// link closes, the command ends with the link's cause, the close frame is offered and the
/// stream is shut down. A failed read does the same.
#[test]
fn a_transport_end_mid_command_closes_the_link_and_ends_the_command() {
    for failed in [false, true] {
        let (mut world, mut pump, mut guest) = booted();
        let exe = execution(NAME);
        let stream = world
            .host_mut()
            .start_command(&exe, request(b"cat\n", 1_024))
            .unwrap();
        pump.flush(world.host_mut());
        guest.read();
        guest.accept(2, 1_024);
        guest.output(2, b"half");
        let mut events = Vec::new();
        if failed {
            guest.wire.borrow_mut().read_error = Some(ErrorKind::ConnectionReset);
        } else {
            // The guest's last bytes are read in one step and its end in the next.
            guest.wire.borrow_mut().guest_ended = true;
            events.extend(pump.step(world.host_mut()));
        }
        events.extend(pump.step(world.host_mut()));
        let results = ended(&events);
        assert_eq!(results.len(), 1, "{events:?}");
        assert_eq!(results[0].stream, stream);
        assert_eq!(
            results[0].end,
            CommandEnd::LinkClosed {
                cause: CloseCause::PeerDisconnected
            }
        );
        let end = if failed {
            assert!(results[0].output.bytes().is_empty());
            let failure = TransportFailure {
                operation: TransportOperation::Read,
                kind: FailureKind::ConnectionReset,
                os_error: None,
            };
            assert_eq!(
                events.first(),
                Some(&PumpEvent::Transport(TransportEvent::Failed { failure }))
            );
            TransportEnd::Failed { failure }
        } else {
            // The bytes before the end were taken, then the end.
            assert_eq!(results[0].output.bytes(), b"half");
            assert!(events.contains(&PumpEvent::Transport(TransportEvent::PeerEnded)));
            TransportEnd::PeerEnded
        };
        assert_eq!(
            events[events.len() - 2..].to_vec(),
            vec![
                PumpEvent::ShutDown { failure: None },
                PumpEvent::Transport(TransportEvent::Finished { end }),
            ]
        );
        assert!(deliveries(&events)
            .iter()
            .any(|delivery| delivery.closed == Some(CloseCause::PeerDisconnected)));
        assert_eq!(pump.phase(), DriverPhase::Finished { end });
        let session = world.host().session(&exe).unwrap();
        assert!(session.is_open() && !session.takes_bytes());
        assert_eq!(session.running_commands(), 0);
        if !failed {
            let messages = guest.read();
            assert_eq!(close_reason(&messages), Some(CloseReason::Orderly));
        }
    }
}

/// Frames recorded on an earlier connection of the boot, the guest's hello among them,
/// are refused on the next connection with a typed reason and close it; a guest that
/// answers that connection's own challenge opens the one after. A second pump for a
/// connection already carried is refused.
#[test]
fn a_frame_from_an_earlier_connection_is_refused() {
    let (mut world, mut pump, mut guest) = booted();
    let exe = execution(NAME);
    let first = connection_nonce(NAME, 1).connection();
    let recorded = guest.sealed(&LinkMessage::Ping { nonce: 77 });
    guest.wire.borrow_mut().to_host.extend(recorded.clone());
    let events = pump.step(world.host_mut());
    assert!(deliveries(&events).iter().any(|delivery| delivery
        .other
        .contains(&LinkEvent::Request(GuestRequest::Ping { nonce: 77 }))));
    guest.wire.borrow_mut().guest_ended = true;
    pump.step(world.host_mut());
    assert!(pump.is_finished());

    // Connection 2: the recorded hello and ping are refused.
    let second = world.next_nonce(NAME);
    world
        .host_mut()
        .reconnect(&exe, secret(NAME), second)
        .unwrap();
    let (wire, state) = Wire::served_by(QEMU.pid);
    let mut pump = SessionPump::new(
        world.host_mut(),
        exe.clone(),
        checked(wire),
        DriverLimits::default(),
    )
    .unwrap();
    let mut reader = Guest::on(&world, &state);
    let mut old = Guest::on(&world, &state);
    // The old guest's frames, sealed for connection 1 as recorded there.
    old.end.read(&[connection_challenge(&world, 1)]);
    let mut bytes = old.sealed(&Guest::hello());
    bytes.extend(recorded);
    state.borrow_mut().to_host.extend(bytes);
    let events = pump.step(world.host_mut());
    let reason = RefusalReason::StaleConnection {
        frame: first,
        bound: second.connection(),
    };
    let delivered = deliveries(&events);
    assert_eq!(delivered.len(), 1, "{events:?}");
    assert!(delivered[0].reports.is_empty());
    assert_eq!(
        delivered[0].other,
        vec![LinkEvent::Refused(Refusal {
            reason: reason.clone(),
            effect: RefusalEffect::LinkClosed
        })]
    );
    assert_eq!(
        delivered[0].closed,
        Some(CloseCause::Violation(reason.clone()))
    );
    assert!(pump.is_finished());
    let messages = reader.read();
    assert!(matches!(messages[0], LinkMessage::Challenge { .. }));
    assert_eq!(
        close_reason(&messages),
        Some(CloseReason::ProtocolViolation)
    );

    // Connection 3: a guest answering this connection's challenge opens it.
    let third = world.next_nonce(NAME);
    world
        .host_mut()
        .reconnect(&exe, secret(NAME), third)
        .unwrap();
    let (wire, state) = Wire::served_by(QEMU.pid);
    let mut pump = SessionPump::new(
        world.host_mut(),
        exe.clone(),
        checked(wire),
        DriverLimits::default(),
    )
    .unwrap();
    let mut guest = Guest::on(&world, &state);
    handshake(&mut world, &mut pump, &mut guest, Some(3));
    let (wire, _) = Wire::served_by(QEMU.pid);
    assert!(matches!(
        SessionPump::new(
            world.host_mut(),
            exe.clone(),
            checked(wire),
            DriverLimits::default()
        ),
        Err(PumpRefusal::ConnectionStarted { sent_frames: 2 })
    ));
}

/// The challenge frame of connection `number`, as the host sealed it.
fn connection_challenge(world: &World, number: u32) -> Vec<u8> {
    let binding = LinkBinding::new(world.vm(NAME), world.boot(NAME), secret(NAME));
    let connection = connection_nonce(NAME, number).connection();
    encode_frame_on(
        &binding,
        connection,
        Sender::Host,
        1,
        &LinkMessage::Challenge { connection },
    )
    .unwrap()
}

/// The link socket of the launch is admitted only when its peer is the QEMU process the
/// host started; a stream served by any other process is refused before a byte is read,
/// and the boot's link is untouched. The admitted stream carries the link through a pump.
#[test]
fn a_peer_that_is_not_the_qemu_process_is_refused_before_any_byte_is_read() {
    let mut world = World::new();
    let exe = execution(NAME);
    world.launch(NAME, SandboxClass::Task);
    let setup = world.setup(NAME);
    world.host_mut().open_channels(&exe, setup).unwrap();
    let directory = PrivateDirectory::new(
        HostPath::new(PathStyle::Windows, r"C:\Yougori\vm\exe-task").unwrap(),
    )
    .unwrap();
    let endpoint = LinkSocketEndpoint::new(&directory, QEMU);
    assert_eq!(
        endpoint.socket().as_str(),
        r"C:\Yougori\vm\exe-task\link.sock"
    );

    let (wire, state) = Wire::served_by(QEMU.pid + 1);
    state.borrow_mut().to_host.extend([0x59u8; 64]);
    assert_eq!(
        endpoint.admit(wire, &Processes).unwrap_err(),
        EndpointRefusal::WrongPeer {
            peer_pid: QEMU.pid + 1,
            vmm: QEMU
        }
    );
    assert_eq!(state.borrow().reads, 0);
    assert_eq!(state.borrow().to_host.len(), 64);
    let link = world.host().session(&exe).unwrap().link().unwrap();
    assert_eq!(link.last_sent_sequence(), 0);
    assert_eq!(link.last_received_sequence(), 0);

    let (wire, state) = Wire::served_by(QEMU.pid);
    let checked = endpoint.admit(wire, &Processes).unwrap();
    assert_eq!(checked.peer(), QEMU);
    let mut pump = SessionPump::new(
        world.host_mut(),
        exe.clone(),
        checked,
        DriverLimits::default(),
    )
    .unwrap();
    assert_eq!(pump.step(world.host_mut()), vec![]);
    let mut guest = Guest::on(&world, &state);
    assert!(matches!(&guest.read()[..], [LinkMessage::Challenge { .. }]));
}

/// What a command refuses before anything reaches the link: oversized input, an output
/// limit of zero or above the ceiling, a zero time limit, and a link before its handshake.
#[test]
fn a_command_is_refused_before_the_handshake_and_outside_its_bounds() {
    let mut world = World::new();
    let exe = execution(NAME);
    world.launch(NAME, SandboxClass::Task);
    let setup = world.setup(NAME);
    world.host_mut().open_channels(&exe, setup).unwrap();
    assert_eq!(
        world.host_mut().start_command(&exe, request(b"", 1)),
        Err(HostError::LinkNotOpen {
            execution: exe.clone()
        })
    );
    let (mut world, _pump, _guest) = booted();
    let host = world.host_mut();
    let input = vec![0u8; MAX_COMMAND_INPUT_BYTES + 1];
    assert_eq!(
        host.start_command(&exe, request(&input, 1)),
        Err(HostError::Command(CommandRefusal::InputTooLarge {
            input_bytes: MAX_COMMAND_INPUT_BYTES + 1,
            max_bytes: MAX_COMMAND_INPUT_BYTES
        }))
    );
    for limit in [0, super::MAX_COMMAND_OUTPUT_BYTES + 1] {
        assert!(matches!(
            host.start_command(&exe, request(b"", limit)),
            Err(HostError::Command(CommandRefusal::OutputLimit { .. }))
        ));
    }
    assert_eq!(
        host.start_command(
            &exe,
            CommandRequest {
                time_limit: Duration::ZERO,
                ..request(b"", 1)
            }
        ),
        Err(HostError::Command(CommandRefusal::ZeroTimeLimit))
    );
    assert_eq!(host.session(&exe).unwrap().running_commands(), 0);
    assert!(!format!("{:?}", request(b"secret input", 1)).contains("secret"));
}

/// Forty commands in a row on one boot, each cut off by its output limit while its input
/// is still queued behind a stream that takes no bytes and while more output is on its
/// way: the guest's credit for output and the host's credit for input come back whole
/// after every one, and a command after them all still runs to its exit.
#[test]
fn many_output_limited_commands_in_a_row_keep_both_windows_whole() {
    let (mut world, mut pump, mut guest) = booted();
    let exe = execution(NAME);
    let window = LinkLimits::default().terminal.max_buffered_bytes;
    // What the guest may still send, as it counts it.
    let mut guest_credit = window;
    // The credit the guest gives the host for input, once; it grants again what it reads.
    let grant: u32 = 65_536;
    guest.send(&LinkMessage::WindowUpdate {
        channel: Channel::Terminal,
        credit_bytes: grant,
    });
    pump.step(world.host_mut());
    let input = vec![b'x'; 40_000];

    for round in 0..40 {
        let stream = world
            .host_mut()
            .start_command(&exe, request(&input, 4))
            .unwrap();
        pump.flush(world.host_mut());
        assert!(matches!(&guest.read()[..], [LinkMessage::Open { .. }]));
        guest.send(&LinkMessage::Opened {
            channel: Channel::Terminal,
            stream,
        });
        // The host queues the input, three frames and its end, but the stream takes none.
        guest.wire.borrow_mut().write_blocked = true;
        pump.step(world.host_mut());
        // The output passes the limit: the host cancels with most of the input queued.
        guest.output(stream.get(), &[b'o'; 64]);
        guest_credit -= 64;
        let events = pump.step(world.host_mut());
        let results = ended(&events);
        assert_eq!(results.len(), 1, "round {round}: {events:?}");
        assert_eq!(results[0].end, CommandEnd::OutputLimitReached);
        // More output was already on its way.
        guest.output(stream.get(), &[b'o'; 512]);
        guest_credit -= 512;
        pump.step(world.host_mut());
        guest.wire.borrow_mut().write_blocked = false;
        pump.flush(world.host_mut());
        // The guest reads what reached it, counts the host's credit and grants again what
        // it read.
        for message in guest.read() {
            match message {
                LinkMessage::WindowUpdate { credit_bytes, .. } => {
                    guest_credit += u64::from(credit_bytes)
                }
                LinkMessage::Data { bytes, .. } => guest.send(&LinkMessage::WindowUpdate {
                    channel: Channel::Terminal,
                    credit_bytes: u32::try_from(bytes.len()).unwrap(),
                }),
                LinkMessage::Cancel { .. } | LinkMessage::EndOfStream { .. } => {}
                other => panic!("round {round}: {other:?}"),
            }
        }
        pump.step(world.host_mut());
        pump.flush(world.host_mut());
        assert_eq!(guest_credit, window, "round {round}: the guest's credit");
        let link = world.host().session(&exe).unwrap().link().unwrap();
        let terminal = link.channel(Channel::Terminal);
        assert_eq!(
            terminal.send_credit_bytes,
            u64::from(grant),
            "round {round}: the host's credit"
        );
        assert_eq!(terminal.receive_window_bytes, window, "round {round}");
        assert_eq!(terminal.streams, 0, "round {round}");
    }

    let stream = world
        .host_mut()
        .start_command(&exe, request(&input, 64))
        .unwrap();
    pump.flush(world.host_mut());
    guest.read();
    guest.send(&LinkMessage::Opened {
        channel: Channel::Terminal,
        stream,
    });
    let events = pump.step(world.host_mut());
    assert!(commands(&events).contains(&CommandEvent::InputEnded {
        stream,
        input_bytes: 40_000
    }));
    guest.output(stream.get(), b"done\n");
    guest.send(&LinkMessage::Exit { stream, code: 0 });
    let events = pump.step(world.host_mut());
    let results = ended(&events);
    assert_eq!(results.len(), 1, "{events:?}");
    assert_eq!(results[0].exit_code(), Some(0));
    assert_eq!(results[0].output.bytes(), b"done\n");
}

/// A reconnect with a nonce a link of the boot used is refused; a nonce drawn from the
/// operating system's generator opens the next connection.
#[test]
fn a_reconnect_with_a_used_nonce_is_refused_and_a_drawn_one_opens() {
    let (mut world, mut pump, guest) = booted();
    let exe = execution(NAME);
    guest.wire.borrow_mut().guest_ended = true;
    pump.step(world.host_mut());
    assert!(pump.is_finished());
    assert_eq!(
        world
            .host_mut()
            .reconnect(&exe, secret(NAME), connection_nonce(NAME, 1)),
        Err(HostError::ConnectionReused {
            execution: exe.clone(),
            boot: world.boot(NAME)
        })
    );
    let drawn = ConnectionNonce::draw().unwrap();
    world
        .host_mut()
        .reconnect(&exe, secret(NAME), drawn)
        .unwrap();
    let session = world.host().session(&exe).unwrap();
    assert!(session.used_connection(drawn.connection()));
    assert_eq!(session.link().unwrap().connection(), drawn.connection());
    let (wire, state) = Wire::served_by(QEMU.pid);
    let mut pump = SessionPump::new(
        world.host_mut(),
        exe.clone(),
        checked(wire),
        DriverLimits::default(),
    )
    .unwrap();
    let mut guest = Guest::on(&world, &state);
    handshake(&mut world, &mut pump, &mut guest, None);
    assert_eq!(guest.end.connection(), drawn.connection());
}

/// The welcome carries no windows, so the guest sends as far as the protocol's; limits
/// whose bulk windows differ are refused before anything opens.
#[test]
fn channels_whose_windows_are_not_the_protocols_are_refused() {
    let mut world = World::new();
    let exe = execution(NAME);
    world.launch(NAME, SandboxClass::Task);
    for channel in [Channel::Terminal, Channel::Egress] {
        let mut setup = world.setup(NAME);
        let quota = match channel {
            Channel::Terminal => &mut setup.link_limits.terminal,
            _ => &mut setup.link_limits.egress,
        };
        let protocol_bytes = quota.max_buffered_bytes;
        quota.max_buffered_bytes = protocol_bytes / 2;
        assert_eq!(
            world.host_mut().open_channels(&exe, setup),
            Err(HostError::NonProtocolWindow {
                channel,
                window_bytes: protocol_bytes / 2,
                protocol_bytes
            })
        );
        assert!(world.host().session(&exe).is_none());
    }
    let mut setup = world.setup(NAME);
    setup.link_limits.terminal.max_queued_frames = 64;
    world.host_mut().open_channels(&exe, setup).unwrap();
    assert!(HostError::NonProtocolWindow {
        channel: Channel::File,
        window_bytes: 1,
        protocol_bytes: 2
    }
    .to_string()
    .contains("file"));
}

/// The guest's time to answer starts when the pump writes the challenge, not when the
/// host opened the channels: a slow start of QEMU and its socket costs the guest nothing.
#[test]
fn the_hello_clock_starts_when_the_challenge_is_written() {
    let mut world = World::new();
    let exe = execution(NAME);
    world.launch(NAME, SandboxClass::Task);
    let setup = world.setup(NAME);
    world.host_mut().open_channels(&exe, setup).unwrap();
    world.advance(30 * SECOND);
    world.host_mut().tick().unwrap();
    assert!(world.host().session(&exe).unwrap().takes_bytes());

    let (wire, state) = Wire::served_by(QEMU.pid);
    let mut pump = SessionPump::new(
        world.host_mut(),
        exe.clone(),
        checked(wire),
        DriverLimits::default(),
    )
    .unwrap();
    pump.step(world.host_mut());
    let mut guest = Guest::on(&world, &state);
    assert!(matches!(&guest.read()[..], [LinkMessage::Challenge { .. }]));
    world.advance(10 * SECOND);
    world.host_mut().tick().unwrap();
    assert!(
        world.host().session(&exe).unwrap().takes_bytes(),
        "ten seconds are within"
    );
    world.advance(SECOND);
    let tick = world.host_mut().tick().unwrap();
    assert!(tick
        .deliveries
        .iter()
        .any(|(_, delivery)| delivery.closed == Some(CloseCause::HandshakeTimedOut)));
    assert!(!world.host().session(&exe).unwrap().takes_bytes());
    pump.step(world.host_mut());
    assert!(pump.is_finished());
}

fn ingress(events: &[PumpEvent]) -> Vec<IngressEvent> {
    deliveries(events)
        .into_iter()
        .flat_map(|delivery| delivery.ingress.clone())
        .collect()
}

/// PROVES the host's ingress stream end to end over the pump (M14): the open names the
/// guest listener; bytes written before the guest answered wait for its `Opened`, then go
/// out within the stream's own window (no channel grant: protocol 3); the guest service's
/// bytes reach the caller as events and are credited back to the stream only once the
/// caller took them; the host's end and the guest's end finish the stream.
#[test]
fn an_ingress_stream_carries_both_directions_once_the_guest_answered() {
    let (mut world, mut pump, mut guest) = booted();
    let exe = execution(NAME);
    let listener = LinkName::new("port-8080").unwrap();
    let stream = world
        .host_mut()
        .open_ingress(&exe, listener.clone())
        .unwrap();
    assert_eq!(stream.get(), 2, "host-opened ingress streams are even");
    const REQUEST: &[u8] = b"GET / HTTP/1.1\r\nhost: preview\r\n\r\n";
    assert_eq!(
        world
            .host_mut()
            .write_ingress(&exe, stream, REQUEST)
            .unwrap(),
        vec![]
    );
    pump.flush(world.host_mut());
    // Only the open: the request waits for the answer.
    assert_eq!(
        guest.read(),
        vec![LinkMessage::Open {
            stream,
            open: StreamOpen::Ingress { listener }
        }]
    );
    guest.send(&LinkMessage::Opened {
        channel: Channel::Ingress,
        stream,
    });
    let events = pump.step(world.host_mut());
    assert_eq!(ingress(&events), vec![IngressEvent::Opened { stream }]);
    pump.flush(world.host_mut());
    assert_eq!(
        guest.read(),
        vec![LinkMessage::Data {
            channel: Channel::Ingress,
            stream,
            bytes: REQUEST.to_vec()
        }]
    );
    // More than a quarter of the stream's first window, so the credit goes back in one.
    let response: Vec<u8> = [
        b"HTTP/1.1 200 OK\r\ncontent-length: 20000\r\n\r\n".as_slice(),
        &[b'y'; 20_000],
    ]
    .concat();
    guest.send(&LinkMessage::Data {
        channel: Channel::Ingress,
        stream,
        bytes: response.clone(),
    });
    let events = pump.step(world.host_mut());
    assert_eq!(
        ingress(&events),
        vec![IngressEvent::Data {
            stream,
            bytes: response.clone()
        }]
    );
    // No credit back until the caller took the bytes: the guest is held to its pace.
    assert_eq!(guest.read(), vec![]);
    world
        .host_mut()
        .consume_ingress(&exe, stream, response.len() as u64)
        .unwrap();
    pump.flush(world.host_mut());
    assert_eq!(
        guest.read(),
        vec![LinkMessage::StreamWindowUpdate {
            channel: Channel::Ingress,
            stream,
            credit_bytes: response.len() as u32
        }],
        "the guest's bytes are credited back to their stream once taken"
    );
    assert_eq!(world.host_mut().end_ingress(&exe, stream).unwrap(), vec![]);
    pump.flush(world.host_mut());
    assert_eq!(
        guest.read(),
        vec![LinkMessage::EndOfStream {
            channel: Channel::Ingress,
            stream
        }]
    );
    guest.send(&LinkMessage::EndOfStream {
        channel: Channel::Ingress,
        stream,
    });
    let events = pump.step(world.host_mut());
    assert_eq!(
        ingress(&events),
        vec![
            IngressEvent::GuestEnded { stream },
            IngressEvent::Ended {
                stream,
                cause: IngressEndCause::Finished
            },
        ]
    );
    assert_eq!(world.host().session(&exe).unwrap().ingress_streams(), 0);
    // The next open takes the next even id.
    let next = world
        .host_mut()
        .open_ingress(&exe, LinkName::new("port-8080").unwrap())
        .unwrap();
    assert_eq!(next.get(), 4);
}

/// PROVES a refused ingress open ends the stream with the guest's cause, and the stream is
/// gone for writes; and that an open before the handshake is refused.
#[test]
fn a_refused_ingress_open_ends_the_stream() {
    let (mut world, mut pump, mut guest) = booted();
    let exe = execution(NAME);
    let stream = world
        .host_mut()
        .open_ingress(&exe, LinkName::new("port-9").unwrap())
        .unwrap();
    pump.flush(world.host_mut());
    guest.read();
    guest.send(&LinkMessage::OpenRefused {
        channel: Channel::Ingress,
        stream,
        cause: OpenRefusalCause::Unavailable,
    });
    let events = pump.step(world.host_mut());
    assert_eq!(
        ingress(&events),
        vec![IngressEvent::Refused {
            stream,
            cause: OpenRefusalCause::Unavailable
        }]
    );
    assert!(matches!(
        world.host_mut().write_ingress(&exe, stream, b"x"),
        Err(HostError::Ingress {
            refusal: IngressRefusal::UnknownStream { .. },
            ..
        })
    ));
}

/// PROVES the host's closure of the channels (a revocation) ends every open ingress stream
/// with the closure's cause, and the guest is sent nothing more for it.
#[test]
fn a_revocation_ends_the_open_ingress_streams() {
    let (mut world, mut pump, mut guest) = booted();
    let exe = execution(NAME);
    let stream = world
        .host_mut()
        .open_ingress(&exe, LinkName::new("port-8080").unwrap())
        .unwrap();
    pump.flush(world.host_mut());
    guest.read();
    guest.send(&LinkMessage::Opened {
        channel: Channel::Ingress,
        stream,
    });
    pump.step(world.host_mut());
    world.host_mut().take_log();
    world
        .host_mut()
        .revoke(&exe, RevocationCause::UserRequested)
        .unwrap();
    let log = world.host_mut().take_log();
    let closure = log.closure_of(&exe).unwrap();
    assert_eq!(
        closure.ingress,
        vec![IngressEvent::Ended {
            stream,
            cause: IngressEndCause::HostClosed {
                closure: ClosureCause::Revoked
            }
        }]
    );
    assert!(world
        .host_mut()
        .write_ingress(&exe, stream, b"late")
        .is_err());
}

fn egress(events: &[PumpEvent]) -> Vec<super::EgressEvent> {
    deliveries(events)
        .into_iter()
        .flat_map(|delivery| delivery.egress.clone())
        .collect()
}

/// PROVES a sandbox connection's egress stream (M14): an open naming one of the boot's
/// connection endpoints is accepted with no port attached (any other is refused), and its
/// bytes are credited back to the stream only as the connection consumes them, in one
/// update once a quarter of the stream's window is due; a stream that ended took its window
/// with it, so nothing is credited for what it held (protocol 3).
#[test]
fn a_connection_endpoints_stream_is_accepted_without_a_port_and_credited_as_consumed() {
    use super::EgressEvent;
    use crate::sandbox::link::StreamId;
    let (mut world, mut pump, mut guest) = booted();
    let exe = execution(NAME);
    let api = LinkName::new("api").unwrap();
    world
        .host_mut()
        .accept_connections(&exe, std::collections::BTreeSet::from([api.clone()]))
        .unwrap();
    let elsewhere = StreamId::new(1).unwrap();
    guest.send(&LinkMessage::Open {
        stream: elsewhere,
        open: StreamOpen::Egress {
            destination: LinkName::new("example").unwrap(),
        },
    });
    let events = pump.step(world.host_mut());
    assert!(matches!(
        &egress(&events)[..],
        [EgressEvent::Refused { .. }]
    ));
    pump.flush(world.host_mut());
    assert!(matches!(
        &guest.read()[..],
        [LinkMessage::OpenRefused {
            channel: Channel::Egress,
            ..
        }]
    ));

    let stream = StreamId::new(3).unwrap();
    guest.send(&LinkMessage::Open {
        stream,
        open: StreamOpen::Egress {
            destination: api.clone(),
        },
    });
    let events = pump.step(world.host_mut());
    assert_eq!(
        egress(&events),
        vec![EgressEvent::Opened {
            stream,
            destination: api
        }]
    );
    pump.flush(world.host_mut());
    assert_eq!(
        guest.read(),
        vec![LinkMessage::Opened {
            channel: Channel::Egress,
            stream
        }]
    );
    guest.send(&LinkMessage::Data {
        channel: Channel::Egress,
        stream,
        bytes: vec![7; 40_000],
    });
    let events = pump.step(world.host_mut());
    assert_eq!(
        egress(&events),
        vec![EgressEvent::Data {
            stream,
            bytes: vec![7; 40_000]
        }]
    );
    pump.flush(world.host_mut());
    assert_eq!(
        guest.read(),
        vec![],
        "nothing is credited before it is consumed"
    );
    world
        .host_mut()
        .consume_egress(&exe, stream, 10_000)
        .unwrap();
    pump.flush(world.host_mut());
    assert_eq!(
        guest.read(),
        vec![],
        "less than a quarter of the window is due"
    );
    world
        .host_mut()
        .consume_egress(&exe, stream, 10_000)
        .unwrap();
    pump.flush(world.host_mut());
    assert_eq!(
        guest.read(),
        vec![LinkMessage::StreamWindowUpdate {
            channel: Channel::Egress,
            stream,
            credit_bytes: 20_000
        }]
    );
    guest.send(&LinkMessage::Cancel {
        channel: Channel::Egress,
        stream,
        cause: CancelCause::Requested,
    });
    pump.step(world.host_mut());
    pump.flush(world.host_mut());
    assert_eq!(
        guest.read(),
        vec![],
        "the stream's window went with it: nothing is credited for what it held"
    );
}
