//! Tests of the transport driver on in-memory duplex streams: partial reads, bounded
//! reads and writes, backpressure, an oversized header and other unauthenticated bytes
//! before authentication, a peer or a writer that goes away mid-frame, typed transport
//! failures, timeouts, a used-up sequence, and recovery on a new connection that refuses
//! the frames of earlier ones.

use std::cell::RefCell;
use std::collections::VecDeque;
use std::io::{self, ErrorKind, Read, Write};
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;

use crate::foundation::coordination::VmInstanceId;
use crate::foundation::ids::{digest, ManualClock, MonotonicTime, SandboxBootGeneration};
use crate::sandbox::link::{
    encode_frame_on, split_frame, BootstrapSecret, Channel, CloseCause, CloseReason, Connection,
    ConnectionNonce, FrameHeader, FramingRefusal, GuestRequest, Hello, HostMessage, LimitsError,
    LinkBinding, LinkEvent, LinkLimits, LinkMessage, LinkPhase, Operation, Refusal, RefusalEffect,
    RefusalReason, ReportBody, Sender, FRAME_OVERHEAD_BYTES, HEADER_BYTES, PROTOCOL_VERSION,
    TAG_BYTES,
};

use super::driver::{
    Closure, DriverEvent, DriverLimits, DriverLimitsError, DriverPhase, DriverSetupError,
    FailureKind, LinkDriver, TransportEnd, TransportEvent, TransportFailure, TransportOperation,
};

const BOOT: u64 = 9;

fn secret(seed: u8) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = (index as u8).wrapping_mul(29).wrapping_add(seed);
    }
    bytes
}

fn vm() -> VmInstanceId {
    VmInstanceId::new(digest("yougori/link/transport/test/v1", &[b"vm"]))
}

fn binding_with(seed: u8) -> LinkBinding {
    LinkBinding::new(
        vm(),
        SandboxBootGeneration::new(BOOT),
        BootstrapSecret::new(&secret(seed)).unwrap(),
    )
}

fn binding() -> LinkBinding {
    binding_with(7)
}

fn hello() -> LinkMessage {
    LinkMessage::Hello(Hello {
        guest_version: PROTOCOL_VERSION,
        agent_build: digest("yougori/link/transport/test/v1", &[b"agent"]),
        claimed_vm: Some(vm().digest()),
        claimed_boot: Some(BOOT),
    })
}

/// The host's draw for connection `seed` of the boot.
fn nonce(seed: u8) -> ConnectionNonce {
    let mut material = [0u8; 16];
    for (index, byte) in material.iter_mut().enumerate() {
        *byte = (index as u8).wrapping_mul(37).wrapping_add(seed);
    }
    ConnectionNonce::new(&material).unwrap()
}

/// The guest end: seals frames with consecutive sequences under a binding, on one
/// connection.
struct Guest {
    binding: LinkBinding,
    connection: Connection,
    sequence: u64,
}

impl Guest {
    /// The guest of an unchallenged link.
    fn new() -> Self {
        Self::keyed(7)
    }

    /// A writer holding another instance's secret: its frames are well formed and
    /// sealed, but not with the bound guest's key.
    fn keyed(seed: u8) -> Self {
        Self {
            binding: binding_with(seed),
            connection: Connection::UNCHALLENGED,
            sequence: 0,
        }
    }

    /// The guest of a challenged link: it binds to the connection the challenge at the
    /// start of what the host wrote names.
    fn answering(written: &[u8]) -> Self {
        let mut guest = Self::new();
        let parts = split_frame(written).unwrap();
        match guest.read_host(written).first() {
            Some(LinkMessage::Challenge { connection }) => {
                assert_eq!(parts.header.connection, *connection);
                assert_eq!(parts.header.sequence, 1);
                guest.connection = *connection;
            }
            other => panic!("the host's first frame is {other:?}"),
        }
        guest
    }

    fn frame(&mut self, message: &LinkMessage) -> Vec<u8> {
        self.sequence += 1;
        encode_frame_on(
            &self.binding,
            self.connection,
            Sender::Guest,
            self.sequence,
            message,
        )
        .unwrap()
    }

    /// Decodes everything the host wrote, checking each frame's host tag.
    fn read_host(&self, mut bytes: &[u8]) -> Vec<LinkMessage> {
        let mut messages = Vec::new();
        while !bytes.is_empty() {
            let parts = split_frame(bytes).unwrap();
            let length = HEADER_BYTES + parts.payload.len() + TAG_BYTES;
            let head: [u8; HEADER_BYTES] = bytes[..HEADER_BYTES].try_into().unwrap();
            assert!(self
                .binding
                .verify(Sender::Host, &head, &parts.payload, &parts.tag));
            let operation =
                Operation::decode(parts.header.channel, parts.header.operation_code).unwrap();
            messages.push(
                LinkMessage::decode(
                    parts.header.channel,
                    operation,
                    parts.header.stream,
                    &parts.payload,
                    usize::MAX,
                )
                .unwrap(),
            );
            bytes = &bytes[length..];
        }
        messages
    }
}

/// One scripted answer to a read call.
enum ReadStep {
    Bytes(Vec<u8>),
    WouldBlock,
    TimedOut,
    Interrupted,
    /// The peer ended its stream; every later read returns zero too.
    End,
    Fail(ErrorKind),
}

/// One scripted answer to a write call; with none left, writes take everything.
enum WriteStep {
    Take(usize),
    WouldBlock,
    Interrupted,
    Zero,
    Fail(ErrorKind),
}

/// The host's end of an in-memory duplex stream: what the guest side sends is scripted,
/// what the host writes is collected. No pipe, socket or process is involved.
#[derive(Default)]
struct Stream {
    reads: VecDeque<ReadStep>,
    writes: VecDeque<WriteStep>,
    block_writes: bool,
    flush_error: Option<ErrorKind>,
    written: Vec<u8>,
    read_calls: usize,
    flushes: usize,
}

#[derive(Clone, Default)]
struct Shared(Rc<RefCell<Stream>>);

impl Shared {
    fn send(&self, bytes: &[u8]) {
        self.0
            .borrow_mut()
            .reads
            .push_back(ReadStep::Bytes(bytes.to_vec()));
    }

    fn send_bytewise(&self, bytes: &[u8]) {
        for byte in bytes {
            self.send(std::slice::from_ref(byte));
        }
    }

    fn script_read(&self, step: ReadStep) {
        self.0.borrow_mut().reads.push_back(step);
    }

    fn script_write(&self, step: WriteStep) {
        self.0.borrow_mut().writes.push_back(step);
    }

    fn written(&self) -> Vec<u8> {
        self.0.borrow().written.clone()
    }

    fn unread_steps(&self) -> usize {
        self.0.borrow().reads.len()
    }

    fn read_calls(&self) -> usize {
        self.0.borrow().read_calls
    }
}

impl Read for Shared {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let mut stream = self.0.borrow_mut();
        stream.read_calls += 1;
        match stream.reads.pop_front() {
            None | Some(ReadStep::WouldBlock) => Err(ErrorKind::WouldBlock.into()),
            Some(ReadStep::TimedOut) => Err(ErrorKind::TimedOut.into()),
            Some(ReadStep::Interrupted) => Err(ErrorKind::Interrupted.into()),
            Some(ReadStep::Fail(kind)) => Err(kind.into()),
            Some(ReadStep::End) => {
                stream.reads.push_front(ReadStep::End);
                Ok(0)
            }
            Some(ReadStep::Bytes(bytes)) => {
                let count = bytes.len().min(buffer.len());
                buffer[..count].copy_from_slice(&bytes[..count]);
                if count < bytes.len() {
                    stream
                        .reads
                        .push_front(ReadStep::Bytes(bytes[count..].to_vec()));
                }
                Ok(count)
            }
        }
    }
}

impl Write for Shared {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let mut stream = self.0.borrow_mut();
        if stream.block_writes {
            return Err(ErrorKind::WouldBlock.into());
        }
        let take = match stream.writes.pop_front() {
            None => bytes.len(),
            Some(WriteStep::Take(count)) => count.min(bytes.len()),
            Some(WriteStep::WouldBlock) => return Err(ErrorKind::WouldBlock.into()),
            Some(WriteStep::Interrupted) => return Err(ErrorKind::Interrupted.into()),
            Some(WriteStep::Zero) => 0,
            Some(WriteStep::Fail(kind)) => return Err(kind.into()),
        };
        stream.written.extend_from_slice(&bytes[..take]);
        Ok(take)
    }

    fn flush(&mut self) -> io::Result<()> {
        let mut stream = self.0.borrow_mut();
        stream.flushes += 1;
        match stream.flush_error {
            Some(kind) => Err(kind.into()),
            None => Ok(()),
        }
    }
}

type Driver = LinkDriver<Arc<ManualClock>, Shared>;

fn driver_with(limits: DriverLimits) -> (Driver, Shared, Arc<ManualClock>) {
    let clock = Arc::new(ManualClock::new(MonotonicTime::from_nanos(1_000)));
    let stream = Shared::default();
    let driver = LinkDriver::new(
        binding(),
        LinkLimits::default(),
        limits,
        Arc::clone(&clock),
        stream.clone(),
    )
    .unwrap();
    (driver, stream, clock)
}

fn driver() -> (Driver, Shared, Arc<ManualClock>) {
    driver_with(DriverLimits::default())
}

/// A driver of a new link for connection `seed` ([`LinkDriver::connect`]).
fn connect_driver(seed: u8) -> (Driver, Shared, Arc<ManualClock>) {
    let clock = Arc::new(ManualClock::new(MonotonicTime::from_nanos(1_000)));
    let stream = Shared::default();
    let driver = LinkDriver::connect(
        binding(),
        nonce(seed),
        LinkLimits::default(),
        DriverLimits::default(),
        Arc::clone(&clock),
        stream.clone(),
    )
    .unwrap();
    (driver, stream, clock)
}

/// A driver whose link accepted the guest's hello and wrote its welcome.
fn open_driver() -> (Driver, Shared, Arc<ManualClock>, Guest) {
    let (mut driver, stream, clock) = driver();
    let mut guest = Guest::new();
    stream.send(&guest.frame(&hello()));
    let events = driver.step();
    assert!(
        matches!(&events[..], [DriverEvent::Link(LinkEvent::Report(_))]),
        "{events:?}"
    );
    assert!(driver.authenticated());
    (driver, stream, clock, guest)
}

fn link_events(events: &[DriverEvent]) -> Vec<&LinkEvent> {
    events
        .iter()
        .filter_map(|event| match event {
            DriverEvent::Link(event) => Some(event),
            DriverEvent::Transport(_) => None,
        })
        .collect()
}

fn transport_events(events: &[DriverEvent]) -> Vec<TransportEvent> {
    events
        .iter()
        .filter_map(|event| match event {
            DriverEvent::Transport(event) => Some(*event),
            DriverEvent::Link(_) => None,
        })
        .collect()
}

fn violation(reason: RefusalReason) -> Vec<DriverEvent> {
    vec![
        DriverEvent::Link(LinkEvent::Refused(Refusal {
            reason: reason.clone(),
            effect: RefusalEffect::LinkClosed,
        })),
        DriverEvent::Link(LinkEvent::Closed(CloseCause::Violation(reason))),
    ]
}

fn finished(end: TransportEnd) -> DriverEvent {
    DriverEvent::Transport(TransportEvent::Finished { end })
}

fn close_reason(message: &LinkMessage) -> Option<CloseReason> {
    match message {
        LinkMessage::Close { reason } => Some(*reason),
        _ => None,
    }
}

#[test]
fn a_hello_arriving_one_byte_per_read_opens_the_link_and_the_welcome_goes_out() {
    let (mut driver, stream, _clock) = driver();
    let mut guest = Guest::new();
    let frame = guest.frame(&hello());
    stream.send_bytewise(&frame);
    let mut events = Vec::new();
    let mut steps = 0;
    while events.is_empty() {
        events = driver.step();
        steps += 1;
        assert!(driver.link().decoder_buffered_bytes() < frame.len());
        assert!(steps <= frame.len(), "the hello never completed");
    }
    // A short read ends the step, so each step read exactly one byte.
    assert_eq!(steps, frame.len());
    assert_eq!(driver.counters().bytes_read, frame.len() as u64);
    match &events[..] {
        [DriverEvent::Link(LinkEvent::Report(report))] => {
            assert!(matches!(report.body(), ReportBody::Hello(_)));
            assert_eq!(report.vm(), vm());
        }
        other => panic!("{other:?}"),
    }
    assert!(driver.authenticated());
    assert_eq!(driver.link().phase(), &LinkPhase::Open);
    let written = guest.read_host(&stream.written());
    assert!(
        matches!(&written[..], [LinkMessage::Welcome(_)]),
        "{written:?}"
    );
    assert_eq!(driver.counters().frames_written, 1);
    assert_eq!(driver.pending_output_bytes(), 0);
}

#[test]
fn reads_are_bounded_by_the_chunk_and_the_step() {
    let limits = DriverLimits {
        read_chunk_bytes: 64,
        max_reads_per_step: 2,
        ..DriverLimits::default()
    };
    let (mut driver, stream, _clock) = driver_with(limits);
    let mut guest = Guest::new();
    let mut bytes = guest.frame(&hello());
    for nonce in 1..=6 {
        bytes.extend(guest.frame(&LinkMessage::Ping { nonce }));
    }
    stream.send(&bytes);
    let mut events = driver.step();
    assert_eq!(driver.counters().read_calls, 2);
    assert_eq!(driver.counters().bytes_read, 128);
    assert_eq!(stream.unread_steps(), 1);
    let mut steps = 1;
    while stream.unread_steps() > 0 {
        let before = driver.counters().bytes_read;
        events.extend(driver.step());
        assert!(driver.counters().bytes_read - before <= 128);
        steps += 1;
    }
    assert_eq!(steps, bytes.len().div_ceil(128));
    let pings: Vec<u64> = link_events(&events)
        .into_iter()
        .filter_map(|event| match event {
            LinkEvent::Request(GuestRequest::Ping { nonce }) => Some(*nonce),
            _ => None,
        })
        .collect();
    assert_eq!(pings, vec![1, 2, 3, 4, 5, 6]);
    assert_eq!(driver.counters().bytes_read, bytes.len() as u64);
}

#[test]
fn an_oversized_header_before_authentication_closes_the_link_and_nothing_more_is_read() {
    let (mut driver, stream, _clock) = driver();
    let header = FrameHeader {
        channel: Channel::Control,
        operation_code: Operation::Hello.code(),
        stream: 0,
        sequence: 1,
        boot_generation: BOOT,
        payload_bytes: u32::MAX,
        connection: Connection::UNCHALLENGED,
    };
    stream.send(&header.encode());
    stream.send(&[0u8; 4_096]);
    stream.send(&Guest::new().frame(&hello()));
    let events = driver.step();
    let reason = RefusalReason::Framing(FramingRefusal::Oversized {
        frame_bytes: u64::from(u32::MAX) + FRAME_OVERHEAD_BYTES as u64,
        max_frame_bytes: 65_552,
    });
    let mut expected = violation(reason.clone());
    expected.push(finished(TransportEnd::LinkClosed));
    assert_eq!(events, expected);
    assert_eq!(driver.link().decoder_buffered_bytes(), 0);
    // The header was the whole read: the trailing bytes and the real hello stay unread.
    assert_eq!(stream.read_calls(), 1);
    assert_eq!(stream.unread_steps(), 2);
    let written = Guest::new().read_host(&stream.written());
    assert_eq!(
        written.iter().map(close_reason).collect::<Vec<_>>(),
        vec![Some(CloseReason::ProtocolViolation)]
    );
    let closure = driver.closure().unwrap();
    assert_eq!(
        closure,
        Closure {
            cause: CloseCause::Violation(reason),
            authenticated: false,
            end: TransportEnd::LinkClosed,
        }
    );
    assert!(closure.before_authentication());
    assert_eq!(driver.step(), vec![]);
    assert_eq!(stream.read_calls(), 1);
}

#[test]
fn any_writer_without_the_guest_key_can_close_the_link_before_hello_and_nothing_else() {
    let mut bad_magic = b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n".to_vec();
    bad_magic.resize(HEADER_BYTES, b' ');
    let other_key = Guest::keyed(99).frame(&hello());
    let mut guest = Guest::new();
    let mut unsealed = guest.frame(&LinkMessage::Ping { nonce: 1 });
    let last = unsealed.len() - 1;
    unsealed[last] ^= 1;
    for (bytes, reason) in [
        (bad_magic, RefusalReason::Framing(FramingRefusal::BadMagic)),
        (other_key, RefusalReason::Unauthenticated),
        (unsealed, RefusalReason::Unauthenticated),
    ] {
        let (mut driver, stream, _clock) = driver();
        stream.send(&bytes);
        let events = driver.step();
        assert!(
            link_events(&events)
                .iter()
                .all(|event| matches!(event, LinkEvent::Refused(_) | LinkEvent::Closed(_))),
            "{events:?}"
        );
        let closure = driver.closure().unwrap();
        assert_eq!(closure.cause, CloseCause::Violation(reason));
        assert!(closure.before_authentication());
        assert!(!driver.authenticated());
    }
}

#[test]
fn the_peer_ending_mid_frame_is_a_truncation_and_the_close_frame_still_goes_out() {
    let (mut driver, stream, _clock, mut guest) = open_driver();
    let ping = guest.frame(&LinkMessage::Ping { nonce: 4 });
    let have_bytes = HEADER_BYTES + 8;
    stream.send(&ping[..have_bytes]);
    stream.script_read(ReadStep::End);
    assert_eq!(driver.step(), vec![]);
    let events = driver.step();
    let mut expected = vec![DriverEvent::Transport(TransportEvent::PeerEnded)];
    expected.extend(violation(RefusalReason::Framing(
        FramingRefusal::Truncated {
            have_bytes,
            need_bytes: ping.len(),
        },
    )));
    expected.push(finished(TransportEnd::PeerEnded));
    assert_eq!(events, expected);
    let written = guest.read_host(&stream.written());
    assert!(matches!(written[0], LinkMessage::Welcome(_)));
    assert_eq!(
        close_reason(&written[1]),
        Some(CloseReason::ProtocolViolation)
    );
    assert!(driver.closure().unwrap().authenticated);

    let (mut driver, stream, _clock, guest) = open_driver();
    stream.script_read(ReadStep::End);
    assert_eq!(
        driver.step(),
        vec![
            DriverEvent::Transport(TransportEvent::PeerEnded),
            DriverEvent::Link(LinkEvent::Closed(CloseCause::PeerDisconnected)),
            finished(TransportEnd::PeerEnded),
        ]
    );
    let written = guest.read_host(&stream.written());
    assert_eq!(close_reason(&written[1]), Some(CloseReason::Orderly));
}

#[test]
fn the_host_side_failing_mid_frame_fails_the_transport() {
    for (step, failure) in [
        (
            WriteStep::Fail(ErrorKind::BrokenPipe),
            TransportFailure {
                operation: TransportOperation::Write,
                kind: FailureKind::BrokenPipe,
                os_error: None,
            },
        ),
        (
            WriteStep::Zero,
            TransportFailure {
                operation: TransportOperation::Write,
                kind: FailureKind::WriteZero,
                os_error: None,
            },
        ),
    ] {
        let (mut driver, stream, _clock) = driver();
        stream.script_write(WriteStep::Take(10));
        stream.script_write(step);
        stream.send(&Guest::new().frame(&hello()));
        let events = driver.step();
        assert!(matches!(
            &events[0],
            DriverEvent::Link(LinkEvent::Report(_))
        ));
        assert_eq!(
            events[1..],
            [
                DriverEvent::Transport(TransportEvent::Failed { failure }),
                DriverEvent::Link(LinkEvent::Closed(CloseCause::PeerDisconnected)),
                finished(TransportEnd::Failed { failure }),
            ]
        );
        assert_eq!(stream.written().len(), 10);
        assert_eq!(driver.pending_output_bytes(), 0);
        let closure = driver.closure().unwrap();
        assert!(closure.authenticated);
        assert_eq!(closure.end, TransportEnd::Failed { failure });
        assert_eq!(driver.flush(), vec![]);
    }

    let (mut driver, stream, _clock) = driver();
    stream.0.borrow_mut().flush_error = Some(ErrorKind::ConnectionAborted);
    stream.send(&Guest::new().frame(&hello()));
    let events = driver.step();
    assert!(transport_events(&events).contains(&TransportEvent::Failed {
        failure: TransportFailure {
            operation: TransportOperation::Flush,
            kind: FailureKind::ConnectionAborted,
            os_error: None,
        }
    }));
    assert!(driver.is_finished());
}

#[test]
fn partial_writes_and_backpressure_resume_in_order_with_one_frame_held() {
    let (mut driver, stream, _clock) = driver();
    for step in [
        WriteStep::Take(3),
        WriteStep::WouldBlock,
        WriteStep::Take(1),
        WriteStep::Interrupted,
        WriteStep::Take(70),
        WriteStep::WouldBlock,
    ] {
        stream.script_write(step);
    }
    let guest = {
        let mut guest = Guest::new();
        stream.send(&guest.frame(&hello()));
        guest
    };
    driver.step();
    for nonce in 1..=3 {
        driver.send(HostMessage::Ping { nonce }).unwrap();
    }
    let max_frame = driver.link().limits().max_frame_bytes as usize;
    for _ in 0..4 {
        assert!(driver.pending_output_bytes() <= max_frame);
        let events = driver.flush();
        assert_eq!(events, vec![], "{events:?}");
    }
    let written = guest.read_host(&stream.written());
    assert!(matches!(written[0], LinkMessage::Welcome(_)));
    assert_eq!(
        written[1..],
        [
            LinkMessage::Ping { nonce: 1 },
            LinkMessage::Ping { nonce: 2 },
            LinkMessage::Ping { nonce: 3 },
        ]
    );
    assert_eq!(driver.counters().frames_written, 4);
    assert_eq!(
        driver.counters().bytes_written,
        stream.written().len() as u64
    );
    assert_eq!(driver.pending_output_bytes(), 0);
}

#[test]
fn writes_per_call_are_bounded() {
    let limits = DriverLimits {
        max_writes_per_step: 2,
        ..DriverLimits::default()
    };
    let (mut driver, stream, _clock) = driver_with(limits);
    let mut guest = Guest::new();
    stream.send(&guest.frame(&hello()));
    driver.step();
    assert_eq!(driver.counters().write_calls, 1);
    let before = driver.counters().write_calls;
    for nonce in 1..=5 {
        driver.send(HostMessage::Ping { nonce }).unwrap();
    }
    driver.flush();
    assert_eq!(driver.counters().write_calls - before, 2);
    assert_eq!(driver.link().queued_frames(), 3);
    driver.flush();
    driver.flush();
    assert_eq!(driver.link().queued_frames(), 0);
    assert_eq!(guest.read_host(&stream.written()).len(), 6);
}

#[test]
fn output_that_makes_no_progress_stalls_the_transport() {
    let (mut driver, stream, clock) = driver();
    stream.0.borrow_mut().block_writes = true;
    stream.send(&Guest::new().frame(&hello()));
    driver.step();
    assert!(driver.pending_output_bytes() > 0);
    clock.advance(Duration::from_secs(5));
    assert_eq!(driver.tick(), vec![]);
    clock.advance(Duration::from_nanos(1));
    let failure = TransportFailure {
        operation: TransportOperation::Write,
        kind: FailureKind::Stalled,
        os_error: None,
    };
    assert_eq!(
        driver.tick(),
        vec![
            DriverEvent::Transport(TransportEvent::Failed { failure }),
            DriverEvent::Link(LinkEvent::Closed(CloseCause::PeerDisconnected)),
            finished(TransportEnd::Failed { failure }),
        ]
    );
    assert_eq!(stream.written(), Vec::<u8>::new());
}

#[test]
fn a_failed_read_is_typed_and_a_partial_frame_becomes_a_truncation() {
    let (mut driver, stream, _clock) = driver();
    let frame = Guest::new().frame(&hello());
    stream.send(&frame[..20]);
    stream.script_read(ReadStep::Fail(ErrorKind::ConnectionReset));
    assert_eq!(driver.step(), vec![]);
    let failure = TransportFailure {
        operation: TransportOperation::Read,
        kind: FailureKind::ConnectionReset,
        os_error: None,
    };
    let mut expected = vec![DriverEvent::Transport(TransportEvent::Failed { failure })];
    expected.extend(violation(RefusalReason::Framing(
        FramingRefusal::Truncated {
            have_bytes: 20,
            need_bytes: HEADER_BYTES,
        },
    )));
    expected.push(finished(TransportEnd::Failed { failure }));
    assert_eq!(driver.step(), expected);
    assert_eq!(stream.written(), Vec::<u8>::new());
    assert!(driver.closure().unwrap().before_authentication());
}

#[test]
fn would_block_timeouts_and_interrupts_are_not_failures() {
    let (mut driver, stream, _clock) = driver();
    stream.script_read(ReadStep::WouldBlock);
    assert_eq!(driver.step(), vec![]);
    stream.script_read(ReadStep::TimedOut);
    assert_eq!(driver.step(), vec![]);
    stream.script_read(ReadStep::Interrupted);
    stream.send(&Guest::new().frame(&hello()));
    let events = driver.step();
    assert!(matches!(
        &events[..],
        [DriverEvent::Link(LinkEvent::Report(_))]
    ));
    assert_eq!(driver.phase(), DriverPhase::Running);
    assert_eq!(stream.read_calls(), 4);
}

#[test]
fn a_finished_driver_touches_nothing() {
    let (mut driver, stream, clock) = driver();
    stream.script_read(ReadStep::End);
    driver.step();
    assert_eq!(
        driver.phase(),
        DriverPhase::Finished {
            end: TransportEnd::PeerEnded
        }
    );
    let calls = stream.read_calls();
    clock.advance(Duration::from_secs(600));
    assert_eq!(driver.step(), vec![]);
    assert_eq!(driver.tick(), vec![]);
    assert_eq!(driver.flush(), vec![]);
    assert_eq!(stream.read_calls(), calls);
    assert_eq!(
        driver.send(HostMessage::Ping { nonce: 1 }),
        Err(crate::sandbox::link::SendRefusal::LinkClosed)
    );
}

#[test]
fn a_host_close_is_reported_and_its_frame_drained() {
    let (mut driver, stream, _clock, guest) = open_driver();
    stream.send(&[0u8; 8]);
    driver
        .send(HostMessage::Close {
            reason: CloseReason::Shutdown,
        })
        .unwrap();
    assert_eq!(
        driver.step(),
        vec![
            DriverEvent::Link(LinkEvent::Closed(CloseCause::HostClosed {
                reason: CloseReason::Shutdown
            })),
            finished(TransportEnd::LinkClosed),
        ]
    );
    // The step after the close read nothing: the waiting bytes stay unread.
    assert_eq!(stream.read_calls(), 1);
    assert_eq!(stream.unread_steps(), 1);
    let written = guest.read_host(&stream.written());
    assert_eq!(close_reason(&written[1]), Some(CloseReason::Shutdown));
    assert_eq!(written.len(), 2);
}

#[test]
fn a_close_waits_for_the_frame_being_written() {
    let (mut driver, stream, _clock) = driver();
    for step in [
        WriteStep::Take(5),
        WriteStep::WouldBlock,
        WriteStep::WouldBlock,
    ] {
        stream.script_write(step);
    }
    let guest = {
        let mut guest = Guest::new();
        stream.send(&guest.frame(&hello()));
        guest
    };
    driver.step();
    assert!(driver.pending_output_bytes() > 0);
    driver
        .send(HostMessage::Close {
            reason: CloseReason::Orderly,
        })
        .unwrap();
    assert_eq!(driver.phase(), DriverPhase::Running);
    assert_eq!(
        driver.flush(),
        vec![DriverEvent::Link(LinkEvent::Closed(
            CloseCause::HostClosed {
                reason: CloseReason::Orderly
            }
        ))]
    );
    assert_eq!(driver.phase(), DriverPhase::Draining);
    assert_eq!(driver.step(), vec![finished(TransportEnd::LinkClosed)]);
    // Nothing was read while draining, and the half-written welcome was finished before
    // the close frame, so the guest reads both whole.
    assert_eq!(stream.read_calls(), 1);
    let written = guest.read_host(&stream.written());
    assert!(matches!(written[0], LinkMessage::Welcome(_)));
    assert_eq!(close_reason(&written[1]), Some(CloseReason::Orderly));
    assert_eq!(written.len(), 2);
}

#[test]
fn the_handshake_timeout_closes_through_tick() {
    let (mut driver, stream, clock) = driver();
    clock.advance(Duration::from_secs(10));
    assert_eq!(driver.tick(), vec![]);
    clock.advance(Duration::from_nanos(1));
    assert_eq!(
        driver.tick(),
        vec![
            DriverEvent::Link(LinkEvent::Closed(CloseCause::HandshakeTimedOut)),
            finished(TransportEnd::LinkClosed),
        ]
    );
    let written = Guest::new().read_host(&stream.written());
    assert_eq!(close_reason(&written[0]), Some(CloseReason::TimedOut));
    assert!(driver.closure().unwrap().before_authentication());
}

/// M06-LC turned this pinned test into a refusal; its name is kept (tests are cited by
/// name). Frames recorded on an earlier connection of the boot are replayed on a new one
/// and refused there, and the guest of the new connection still opens its link.
#[test]
fn a_closure_before_authentication_is_recovered_by_a_new_link_and_earlier_frames_replay() {
    // Connection 1: some writer sends an oversized header before the guest says hello.
    let (mut first, stream, _clock) = connect_driver(1);
    let mut header = Guest::new().frame(&hello());
    header[28..32].copy_from_slice(&u32::MAX.to_be_bytes());
    stream.send(&header[..HEADER_BYTES]);
    first.step();
    assert!(first.closure().unwrap().before_authentication());

    // Connection 2: a new link for the same VM and boot writes its challenge first and
    // opens when the guest answers it.
    let (mut second, stream, _clock) = connect_driver(2);
    assert_eq!(second.step(), vec![]);
    let mut guest = Guest::answering(&stream.written());
    let mut recorded = guest.frame(&hello());
    recorded.extend(guest.frame(&LinkMessage::Ping { nonce: 77 }));
    stream.send(&recorded);
    let events = second.step();
    assert!(second.authenticated());
    assert!(link_events(&events).contains(&&LinkEvent::Request(GuestRequest::Ping { nonce: 77 })));

    // Connection 3: the bytes recorded on connection 2, replayed verbatim, are refused,
    // because the link binds its connection: the hello names connection 2.
    let (mut third, stream, _clock) = connect_driver(3);
    stream.send(&recorded);
    let events = third.step();
    let reason = RefusalReason::StaleConnection {
        frame: nonce(2).connection(),
        bound: nonce(3).connection(),
    };
    let mut expected = violation(reason.clone());
    expected.push(finished(TransportEnd::LinkClosed));
    assert_eq!(events, expected);
    assert!(!third.authenticated());
    assert_eq!(
        third.closure().unwrap().cause,
        CloseCause::Violation(reason)
    );
    assert_eq!(third.link().last_received_sequence(), 0);
    // What the host wrote on connection 3: its challenge and its close, from sequence 1.
    let written = stream.written();
    let mut rest = &written[..];
    let mut sequences = Vec::new();
    while !rest.is_empty() {
        let parts = split_frame(rest).unwrap();
        assert_eq!(parts.header.connection, nonce(3).connection());
        sequences.push(parts.header.sequence);
        rest = &rest[FRAME_OVERHEAD_BYTES + parts.payload.len()..];
    }
    assert_eq!(sequences, vec![1, 2]);
    let messages = Guest::new().read_host(&written);
    assert_eq!(
        close_reason(&messages[1]),
        Some(CloseReason::ProtocolViolation)
    );

    // Connection 4: the guest answers this connection's own challenge and the link opens.
    let (mut fourth, stream, _clock) = connect_driver(4);
    fourth.step();
    let mut guest = Guest::answering(&stream.written());
    let mut opening = guest.frame(&hello());
    opening.extend(guest.frame(&LinkMessage::Ping { nonce: 78 }));
    stream.send(&opening);
    let events = fourth.step();
    assert!(fourth.authenticated());
    assert!(link_events(&events).contains(&&LinkEvent::Request(GuestRequest::Ping { nonce: 78 })));
}

#[test]
fn the_driver_surfaces_a_used_up_host_sequence_as_the_links_close_event() {
    let (mut driver, stream, _clock, guest) = open_driver();
    let before = stream.written();
    driver.link_mut().set_last_sent_sequence(u64::MAX);
    driver.send(HostMessage::Ping { nonce: 1 }).unwrap();
    assert_eq!(
        driver.flush(),
        vec![
            DriverEvent::Link(LinkEvent::Closed(CloseCause::SequenceExhausted)),
            finished(TransportEnd::LinkClosed),
        ]
    );
    // The link returned the close once, to the driver; no frame could be sealed.
    assert_eq!(driver.link_mut().take_events(), vec![]);
    assert_eq!(stream.written(), before);
    assert_eq!(guest.read_host(&before).len(), 1);
    let closure = driver.closure().unwrap();
    assert_eq!(closure.cause, CloseCause::SequenceExhausted);
    assert!(closure.authenticated);
    assert_eq!(driver.step(), vec![]);
}

#[test]
fn limits_are_validated_before_anything_is_made() {
    assert_eq!(DriverLimits::default().validate(), Ok(()));
    for (limits, error) in [
        (
            DriverLimits {
                read_chunk_bytes: 0,
                ..DriverLimits::default()
            },
            DriverLimitsError::ReadChunk {
                read_chunk_bytes: 0,
                max: 1 << 20,
            },
        ),
        (
            DriverLimits {
                read_chunk_bytes: (1 << 20) + 1,
                ..DriverLimits::default()
            },
            DriverLimitsError::ReadChunk {
                read_chunk_bytes: (1 << 20) + 1,
                max: 1 << 20,
            },
        ),
        (
            DriverLimits {
                max_reads_per_step: 0,
                ..DriverLimits::default()
            },
            DriverLimitsError::ZeroReads,
        ),
        (
            DriverLimits {
                max_writes_per_step: 0,
                ..DriverLimits::default()
            },
            DriverLimitsError::ZeroWrites,
        ),
        (
            DriverLimits {
                write_stall_timeout: Duration::ZERO,
                ..DriverLimits::default()
            },
            DriverLimitsError::ZeroStallTimeout,
        ),
    ] {
        let clock = Arc::new(ManualClock::new(MonotonicTime::ZERO));
        let made = LinkDriver::new(
            binding(),
            LinkLimits::default(),
            limits,
            clock,
            Shared::default(),
        );
        assert_eq!(made.err(), Some(DriverSetupError::Driver(error)));
        assert!(!error.to_string().is_empty());
    }
    let clock = Arc::new(ManualClock::new(MonotonicTime::ZERO));
    let made = LinkDriver::new(
        binding(),
        LinkLimits {
            max_refusals: 0,
            ..LinkLimits::default()
        },
        DriverLimits::default(),
        clock,
        Shared::default(),
    );
    let error = made.err().unwrap();
    assert_eq!(error, DriverSetupError::Link(LimitsError::ZeroRefusals));
    assert_eq!(
        error.to_string(),
        "link limits: max_refusals may not be zero"
    );
    let mut value = serde_json::to_value(DriverLimits::default()).unwrap();
    value["max_frames"] = serde_json::json!(1);
    assert!(serde_json::from_value::<DriverLimits>(value).is_err());
}

#[test]
fn events_and_closures_serialize_with_their_source() {
    let failure = TransportFailure {
        operation: TransportOperation::Read,
        kind: FailureKind::BrokenPipe,
        os_error: Some(109),
    };
    assert_eq!(
        serde_json::to_value(DriverEvent::Transport(TransportEvent::Finished {
            end: TransportEnd::Failed { failure }
        }))
        .unwrap(),
        serde_json::json!({
            "source": "transport",
            "event": {
                "transport": "finished",
                "end": {
                    "end": "failed",
                    "failure": {"operation": "read", "kind": "broken_pipe", "os_error": 109}
                }
            }
        })
    );
    assert_eq!(
        failure.to_string(),
        "transport Read failed: BrokenPipe (os error 109)"
    );
    let (driver, _stream, _clock, _guest) = open_driver();
    assert!(format!("{driver:?}").contains("authenticated: true"));
    assert_eq!(driver.closure(), None);
    assert_eq!(driver.into_transport().read_calls(), 1);
}

#[test]
fn a_hello_and_a_violation_in_one_read_count_as_authenticated() {
    let (mut driver, stream, _clock) = driver();
    let mut guest = Guest::new();
    let mut bytes = guest.frame(&hello());
    bytes.extend_from_slice(b"YGLX");
    bytes.resize(bytes.len() + HEADER_BYTES - 4, 0);
    stream.send(&bytes);
    let events = driver.step();
    assert!(matches!(
        link_events(&events)[..],
        [
            LinkEvent::Report(_),
            LinkEvent::Refused(_),
            LinkEvent::Closed(_)
        ]
    ));
    let closure = driver.closure().unwrap();
    assert!(closure.authenticated);
    assert_eq!(
        closure.cause,
        CloseCause::Violation(RefusalReason::Framing(FramingRefusal::BadMagic))
    );
}

#[test]
fn injected_bytes_close_an_authenticated_link_too() {
    let (mut driver, stream, _clock, mut guest) = open_driver();
    let mut injected = guest.frame(&LinkMessage::Ping { nonce: 5 });
    injected[0] = b'X';
    stream.send(&injected);
    let mut expected = violation(RefusalReason::Framing(FramingRefusal::BadMagic));
    expected.push(finished(TransportEnd::LinkClosed));
    assert_eq!(driver.step(), expected);
    let closure = driver.closure().unwrap();
    assert!(closure.authenticated);
    assert!(!closure.before_authentication());
}

// ---------------------------------------------------------------- close policy (R2)

/// Review finding R2: a revocation never submits old application bytes. A frame the
/// transport has not taken at all is discarded, and only the close frame goes out.
#[test]
fn a_revocation_discards_an_unwritten_frame_and_sends_only_the_close() {
    let (mut driver, stream, _clock, guest) = open_driver();
    stream.script_write(WriteStep::WouldBlock);
    driver.send(HostMessage::Ping { nonce: 7 }).unwrap();
    assert_eq!(driver.flush(), vec![]);
    assert!(
        driver.pending_output_bytes() > 0,
        "the ping waits in the driver"
    );
    let before = stream.written();
    driver
        .send(HostMessage::Close {
            reason: CloseReason::Revoked,
        })
        .unwrap();
    // The next write applies the policy before any byte of the ping could go out.
    assert_eq!(
        driver.flush(),
        vec![
            DriverEvent::Link(LinkEvent::Closed(CloseCause::HostClosed {
                reason: CloseReason::Revoked
            })),
            finished(TransportEnd::LinkClosed),
        ]
    );
    assert_eq!(driver.pending_output_bytes(), 0);
    let written = guest.read_host(&stream.written());
    assert!(matches!(written[0], LinkMessage::Welcome(_)));
    assert_eq!(close_reason(&written[1]), Some(CloseReason::Revoked));
    assert_eq!(written.len(), 2, "the ping never reached the transport");
    assert!(stream.written().starts_with(&before));
    assert_eq!(driver.counters().frames_discarded, 1);
    assert_eq!(driver.counters().frames_written, 2);
    assert_eq!(driver.closure().unwrap().end, TransportEnd::LinkClosed);
}

/// Review finding R2: a frame the transport has partly accepted cannot be recalled and
/// must not be followed by a close frame in its middle. The driver abandons the
/// transport at once, writes nothing more, and states what had reached the transport.
#[test]
fn a_revocation_after_a_partial_write_abandons_the_transport_without_a_close_frame() {
    let (mut driver, stream, _clock, _guest) = open_driver();
    stream.script_write(WriteStep::Take(5));
    stream.script_write(WriteStep::WouldBlock);
    driver.send(HostMessage::Ping { nonce: 7 }).unwrap();
    assert_eq!(driver.flush(), vec![]);
    let rest = driver.pending_output_bytes();
    assert!(rest > 0);
    let frame_bytes = rest + 5;
    let before = stream.written();
    driver
        .send(HostMessage::Close {
            reason: CloseReason::Revoked,
        })
        .unwrap();
    let end = TransportEnd::Aborted {
        reason: CloseReason::Revoked,
        written: 5,
        of: frame_bytes,
    };
    assert_eq!(
        driver.flush(),
        vec![
            DriverEvent::Link(LinkEvent::Closed(CloseCause::HostClosed {
                reason: CloseReason::Revoked
            })),
            finished(end),
        ]
    );
    assert_eq!(
        stream.written(),
        before,
        "nothing more was written: no rest, no close frame"
    );
    assert!(driver.is_finished());
    assert_eq!(driver.pending_output_bytes(), 0);
    assert_eq!(driver.counters().frames_discarded, 0);
    assert_eq!(driver.closure().unwrap().end, end);
    // The abandoned transport is not used again.
    assert_eq!(driver.step(), vec![]);
    assert_eq!(driver.tick(), vec![]);
    assert_eq!(stream.written(), before);
}

/// A lease that runs out closes the link through its idle timeout; like a revocation,
/// that drains nothing: a partly written frame abandons the transport, with the timeout
/// as the reason, even though the write itself had not stalled yet.
#[test]
fn an_idle_timeout_with_a_partly_written_frame_abandons_the_transport() {
    let (mut driver, stream, clock, _guest) = open_driver();
    stream.script_write(WriteStep::Take(5));
    stream.script_write(WriteStep::WouldBlock);
    driver.send(HostMessage::Ping { nonce: 7 }).unwrap();
    assert_eq!(driver.flush(), vec![]);
    // The peer takes nothing more.
    stream.0.borrow_mut().block_writes = true;
    let frame_bytes = driver.pending_output_bytes() + 5;
    let before = stream.written();
    // Under the write stall timeout, then over the idle timeout: the link closes first.
    clock.advance(Duration::from_secs(4));
    assert_eq!(driver.tick(), vec![]);
    clock.advance(Duration::from_secs(57));
    assert_eq!(
        driver.tick(),
        vec![
            DriverEvent::Link(LinkEvent::Closed(CloseCause::IdleTimedOut)),
            finished(TransportEnd::Aborted {
                reason: CloseReason::TimedOut,
                written: 5,
                of: frame_bytes,
            }),
        ]
    );
    assert_eq!(stream.written(), before);
}

/// An unwritten frame under transport backpressure is discarded by a timeout close too,
/// and the close frame goes out once the transport takes bytes again.
#[test]
fn an_idle_timeout_discards_an_unwritten_frame_under_backpressure() {
    let (mut driver, stream, clock, guest) = open_driver();
    stream.0.borrow_mut().block_writes = true;
    driver.send(HostMessage::Ping { nonce: 7 }).unwrap();
    assert_eq!(driver.flush(), vec![]);
    assert!(driver.pending_output_bytes() > 0);
    clock.advance(Duration::from_secs(4));
    assert_eq!(driver.tick(), vec![]);
    clock.advance(Duration::from_secs(57));
    assert_eq!(
        driver.tick(),
        vec![DriverEvent::Link(LinkEvent::Closed(
            CloseCause::IdleTimedOut
        ))]
    );
    assert_eq!(driver.phase(), DriverPhase::Draining);
    assert_eq!(driver.counters().frames_discarded, 1);
    // Only the close frame waits now, taken after the close and so not subject to it.
    assert!(driver.pending_output_bytes() > 0);
    stream.0.borrow_mut().block_writes = false;
    assert_eq!(driver.flush(), vec![finished(TransportEnd::LinkClosed)]);
    let written = guest.read_host(&stream.written());
    assert_eq!(written.len(), 2);
    assert_eq!(close_reason(&written[1]), Some(CloseReason::TimedOut));
}

/// The orderly drain is bounded: a peer that stops taking bytes after an orderly close
/// fails the transport at the write stall timeout rather than holding the frame forever.
#[test]
fn an_orderly_drain_is_bounded_by_the_write_stall_timeout() {
    let (mut driver, stream, clock, _guest) = open_driver();
    stream.script_write(WriteStep::Take(5));
    stream.script_write(WriteStep::WouldBlock);
    driver.send(HostMessage::Ping { nonce: 7 }).unwrap();
    // The first write takes five bytes; then the peer takes nothing more.
    assert_eq!(driver.flush(), vec![]);
    stream.0.borrow_mut().block_writes = true;
    let rest = driver.pending_output_bytes();
    assert!(rest > 0);
    driver
        .send(HostMessage::Close {
            reason: CloseReason::Orderly,
        })
        .unwrap();
    assert_eq!(
        driver.flush(),
        vec![DriverEvent::Link(LinkEvent::Closed(
            CloseCause::HostClosed {
                reason: CloseReason::Orderly
            }
        ))]
    );
    assert_eq!(driver.phase(), DriverPhase::Draining);
    assert_eq!(
        driver.pending_output_bytes(),
        rest,
        "an orderly close keeps draining"
    );
    clock.advance(Duration::from_secs(5));
    assert_eq!(driver.tick(), vec![]);
    clock.advance(Duration::from_nanos(1));
    let failure = TransportFailure {
        operation: TransportOperation::Write,
        kind: FailureKind::Stalled,
        os_error: None,
    };
    assert_eq!(
        driver.tick(),
        vec![
            DriverEvent::Transport(TransportEvent::Failed { failure }),
            finished(TransportEnd::Failed { failure }),
        ]
    );
    assert_eq!(driver.counters().frames_discarded, 0);
}
