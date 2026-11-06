//! Tests of the connection binding (§3.2 line 2067 "generation/connection binding and
//! monotonically checked sequence state"; VM-R59 line 2924 "replay"): a challenged link
//! refuses the frames, acknowledgments, tags and handshake of an earlier connection of the
//! same boot with a typed reason, starts its sequences at 1, still reconnects, and
//! reports a used-up host sequence as a close event; version 1 frames are refused by
//! name.

use std::sync::Arc;

use crate::foundation::coordination::VmInstanceId;
use crate::foundation::ids::{digest, ManualClock, MonotonicTime, SandboxBootGeneration};

use super::connection::{Connection, ConnectionNonce};
use super::corpus::split_frame;
use super::limits::LinkLimits;
use super::link::{
    encode_frame, encode_frame_on, CloseCause, HostLink, LinkEvent, LinkPhase, Refusal,
    RefusalEffect, RefusalReason,
};
use super::messages::{CloseReason, GuestRequest, Hello, HostMessage, LinkMessage, ReportBody};
use super::secret::{BootstrapSecret, LinkBinding};
use super::sequence::SequenceRefusal;
use super::tests::version_1_hello;
use super::wire::{
    Channel, FrameHeader, FramingRefusal, Operation, Sender, HEADER_BYTES, PROTOCOL_VERSION,
};

const BOOT: u64 = 11;

type TestLink = HostLink<Arc<ManualClock>>;

fn binding() -> LinkBinding {
    let mut secret = [0u8; 32];
    for (index, byte) in secret.iter_mut().enumerate() {
        *byte = (index as u8).wrapping_mul(23).wrapping_add(9);
    }
    LinkBinding::new(
        VmInstanceId::new(digest("yougori/link/connection/test/v1", &[b"vm"])),
        SandboxBootGeneration::new(BOOT),
        BootstrapSecret::new(&secret).unwrap(),
    )
}

/// The host's draw for connection `seed` of the boot.
fn nonce(seed: u8) -> ConnectionNonce {
    let mut material = [0u8; 16];
    for (index, byte) in material.iter_mut().enumerate() {
        *byte = (index as u8).wrapping_mul(31).wrapping_add(seed);
    }
    ConnectionNonce::new(&material).unwrap()
}

fn hello() -> LinkMessage {
    LinkMessage::Hello(Hello {
        guest_version: PROTOCOL_VERSION,
        agent_build: digest("yougori/link/connection/test/v1", &[b"agent"]),
        claimed_vm: None,
        claimed_boot: Some(BOOT),
    })
}

fn ping(nonce: u64) -> LinkMessage {
    LinkMessage::Ping { nonce }
}

fn clock() -> Arc<ManualClock> {
    Arc::new(ManualClock::new(MonotonicTime::from_nanos(1_000)))
}

/// A link for connection `seed`.
fn connect(seed: u8) -> TestLink {
    HostLink::connect(binding(), nonce(seed), LinkLimits::default(), clock()).unwrap()
}

/// One host frame as the guest reads it: the host's tag is checked.
fn read_host(frame: &[u8]) -> (FrameHeader, LinkMessage) {
    let parts = split_frame(frame).unwrap();
    assert!(binding().verify(
        Sender::Host,
        &frame[..HEADER_BYTES],
        &parts.payload,
        &parts.tag
    ));
    let operation = Operation::decode(parts.header.channel, parts.header.operation_code).unwrap();
    let message = LinkMessage::decode(
        parts.header.channel,
        operation,
        parts.header.stream,
        &parts.payload,
        usize::MAX,
    )
    .unwrap();
    (parts.header, message)
}

fn drain(link: &mut TestLink) -> Vec<(FrameHeader, LinkMessage)> {
    std::iter::from_fn(|| link.next_outbound())
        .map(|frame| read_host(&frame))
        .collect()
}

/// The guest end of one connection: it binds to the connection the host's challenge
/// names and seals consecutive sequences on it.
struct Guest {
    binding: LinkBinding,
    connection: Connection,
    sequence: u64,
}

impl Guest {
    /// Reads the challenge, the link's first frame.
    fn answering(link: &mut TestLink) -> Self {
        let frame = link.next_outbound().unwrap();
        let (header, message) = read_host(&frame);
        let LinkMessage::Challenge { connection } = message else {
            panic!("the first frame is {message:?}");
        };
        assert_eq!(header.connection, connection);
        Self {
            binding: binding(),
            connection,
            sequence: 0,
        }
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
}

/// A link for connection `seed` that accepted its guest's hello.
fn open(seed: u8) -> (TestLink, Guest) {
    let mut link = connect(seed);
    let mut guest = Guest::answering(&mut link);
    let events = link.receive(&guest.frame(&hello()));
    assert!(matches!(&events[..], [LinkEvent::Report(_)]), "{events:?}");
    assert_eq!(link.phase(), &LinkPhase::Open);
    (link, guest)
}

fn stale(frame: Connection, bound: Connection) -> Vec<LinkEvent> {
    let reason = RefusalReason::StaleConnection { frame, bound };
    vec![
        LinkEvent::Refused(Refusal {
            reason: reason.clone(),
            effect: RefusalEffect::LinkClosed,
        }),
        LinkEvent::Closed(CloseCause::Violation(reason)),
    ]
}

#[test]
fn a_challenged_link_sends_its_nonce_first_and_opens_on_a_bound_hello() {
    let mut link = connect(1);
    assert_eq!(link.connection(), nonce(1).connection());
    assert_eq!(link.phase(), &LinkPhase::AwaitingHello);
    assert_eq!(link.queued_frames(), 1);
    let frame = link.next_outbound().unwrap();
    let (header, message) = read_host(&frame);
    assert_eq!(header.sequence, 1);
    assert_eq!(header.boot_generation, BOOT);
    assert_eq!(header.connection, nonce(1).connection());
    assert_eq!(header.channel, Channel::Control);
    assert_eq!(
        message,
        LinkMessage::Challenge {
            connection: nonce(1).connection()
        }
    );
    assert_eq!(link.next_outbound(), None);

    let mut guest = Guest {
        binding: binding(),
        connection: nonce(1).connection(),
        sequence: 0,
    };
    let events = link.receive(&guest.frame(&hello()));
    let [LinkEvent::Report(report)] = &events[..] else {
        panic!("{events:?}");
    };
    assert!(matches!(report.body(), ReportBody::Hello(_)));
    assert_eq!(report.connection(), nonce(1).connection());
    assert_eq!(report.sequence(), 1);
    let json = serde_json::to_value(report).unwrap();
    assert_eq!(json["connection"], nonce(1).connection().to_hex());
    assert_eq!(link.phase(), &LinkPhase::Open);

    let frames = drain(&mut link);
    assert_eq!(frames.len(), 1);
    assert_eq!(frames[0].0.sequence, 2);
    assert_eq!(frames[0].0.connection, nonce(1).connection());
    assert!(matches!(frames[0].1, LinkMessage::Welcome(_)));
    assert!(Operation::Challenge.is_urgent());
    assert_eq!(
        Operation::Challenge
            .direction(Channel::Control)
            .map(|direction| direction.allows(Sender::Guest)),
        Some(false)
    );
}

#[test]
fn frames_and_acknowledgments_of_an_earlier_connection_are_refused() {
    let (mut first, mut earlier) = open(1);
    let recorded = [
        earlier.frame(&ping(5)),
        earlier.frame(&LinkMessage::Pong { nonce: 6 }),
        earlier.frame(&LinkMessage::WindowUpdate {
            channel: Channel::File,
            credit_bytes: 4_096,
        }),
        earlier.frame(&LinkMessage::Close {
            reason: CloseReason::Orderly,
        }),
    ];
    // Each is accepted on its own connection.
    for frame in &recorded {
        assert!(
            !first
                .receive(frame)
                .iter()
                .any(|event| matches!(event, LinkEvent::Refused(_))),
            "accepted on connection 1"
        );
    }
    for frame in &recorded {
        let (mut second, _guest) = open(2);
        assert_eq!(
            second.receive(frame),
            stale(nonce(1).connection(), nonce(2).connection())
        );
        assert!(second.is_closed());
        assert_eq!(second.channel(Channel::Egress).send_credit_bytes, 0);
        // The close frame goes out on this connection.
        let frames = drain(&mut second);
        let (header, message) = frames.last().unwrap();
        assert_eq!(header.connection, nonce(2).connection());
        assert_eq!(
            message,
            &LinkMessage::Close {
                reason: CloseReason::ProtocolViolation
            }
        );
    }
}

#[test]
fn a_handshake_replayed_from_an_earlier_connection_is_refused() {
    let mut first = connect(1);
    let mut earlier = Guest::answering(&mut first);
    let recorded = [earlier.frame(&hello()), earlier.frame(&ping(77))].concat();
    let events = first.receive(&recorded);
    assert!(events.contains(&LinkEvent::Request(GuestRequest::Ping { nonce: 77 })));

    let mut second = connect(2);
    let events = second.receive(&recorded);
    assert_eq!(events, stale(nonce(1).connection(), nonce(2).connection()));
    assert!(!events
        .iter()
        .any(|event| matches!(event, LinkEvent::Report(_) | LinkEvent::Request(_))));
    assert!(second.is_closed());
    assert_eq!(second.last_received_sequence(), 0);
    assert_eq!(
        RefusalReason::StaleConnection {
            frame: nonce(1).connection(),
            bound: nonce(2).connection(),
        }
        .code(),
        "stale_connection"
    );

    // A hello that ignores the challenge is refused the same way.
    let mut third = connect(3);
    let unchallenged = encode_frame(&binding(), Sender::Guest, 1, &hello()).unwrap();
    assert_eq!(
        third.receive(&unchallenged),
        stale(Connection::UNCHALLENGED, nonce(3).connection())
    );
}

#[test]
fn an_earlier_connections_tag_does_not_cover_this_connection() {
    let mut first = connect(1);
    let mut earlier = Guest::answering(&mut first);
    let mut moved = earlier.frame(&hello());
    moved[32..HEADER_BYTES].copy_from_slice(nonce(2).connection().as_bytes());
    let mut second = connect(2);
    let events = second.receive(&moved);
    assert_eq!(
        events.first(),
        Some(&LinkEvent::Refused(Refusal {
            reason: RefusalReason::Unauthenticated,
            effect: RefusalEffect::LinkClosed,
        }))
    );
    assert!(second.is_closed());

    // The host's own frames are bound the same way: a welcome of connection 1 does not
    // verify as a frame of connection 2.
    let (mut first, _guest) = open(1);
    let welcome = first.next_outbound().unwrap();
    let parts = split_frame(&welcome).unwrap();
    assert_eq!(parts.header.connection, nonce(1).connection());
    let mut header = parts.header;
    header.connection = nonce(2).connection();
    assert!(!binding().verify(Sender::Host, &header.encode(), &parts.payload, &parts.tag));
}

#[test]
fn sequences_start_fresh_on_every_connection() {
    let (mut first, mut earlier) = open(1);
    for nonce in 0..4 {
        first.receive(&earlier.frame(&ping(nonce)));
        first.send(HostMessage::Pong { nonce }).unwrap();
    }
    drain(&mut first);
    assert_eq!(first.last_received_sequence(), 5);
    assert_eq!(first.last_sent_sequence(), 6);

    let mut second = connect(2);
    assert_eq!(second.last_received_sequence(), 0);
    assert_eq!(second.last_sent_sequence(), 0);
    let mut guest = Guest::answering(&mut second);
    assert_eq!(second.last_sent_sequence(), 1);
    second.receive(&guest.frame(&hello()));
    assert_eq!(second.last_received_sequence(), 1);
    assert_eq!(drain(&mut second)[0].0.sequence, 2);
    // Continuing the earlier connection's count is a gap on this one.
    let continued = encode_frame_on(
        &binding(),
        nonce(2).connection(),
        Sender::Guest,
        6,
        &ping(9),
    )
    .unwrap();
    assert_eq!(
        second.receive(&continued)[0],
        LinkEvent::Refused(Refusal {
            reason: RefusalReason::Sequence(SequenceRefusal::Reordered {
                sequence: 6,
                expected: 2
            }),
            effect: RefusalEffect::LinkClosed,
        })
    );
}

#[test]
fn reconnect_works_after_any_closure() {
    // Connection 1 closed by a violation, 2 by the guest, 3 by the transport, 4 by the
    // handshake timeout; each next connection opens and carries requests.
    let (mut first, mut guest) = open(1);
    let mut forged = guest.frame(&ping(1));
    let last = forged.len() - 1;
    forged[last] ^= 1;
    first.receive(&forged);
    assert!(first.is_closed());

    let (mut second, mut guest) = open(2);
    second.receive(&guest.frame(&LinkMessage::Close {
        reason: CloseReason::Orderly,
    }));
    assert!(second.is_closed());

    let (mut third, _guest) = open(3);
    assert_eq!(
        third.peer_closed(),
        vec![LinkEvent::Closed(CloseCause::PeerDisconnected)]
    );

    let clock = clock();
    let mut fourth = HostLink::connect(
        binding(),
        nonce(4),
        LinkLimits::default(),
        Arc::clone(&clock),
    )
    .unwrap();
    // The guest's time to answer starts when the challenge goes to the transport.
    clock.advance(std::time::Duration::from_secs(30));
    assert_eq!(fourth.tick(), vec![]);
    assert!(fourth.next_outbound().is_some());
    clock.advance(std::time::Duration::from_secs(11));
    assert_eq!(
        fourth.tick(),
        vec![LinkEvent::Closed(CloseCause::HandshakeTimedOut)]
    );

    let (mut fifth, mut guest) = open(5);
    assert_eq!(
        fifth.receive(&guest.frame(&ping(3))),
        vec![LinkEvent::Request(GuestRequest::Ping { nonce: 3 })]
    );
    assert_eq!(
        fifth.receive(&guest.frame(&LinkMessage::WindowUpdate {
            channel: Channel::File,
            credit_bytes: 10,
        })),
        vec![LinkEvent::Request(GuestRequest::WindowUpdate {
            channel: Channel::File,
            credit_bytes: 10,
        })]
    );
    assert_eq!(fifth.phase(), &LinkPhase::Open);
}

#[test]
fn unchallenged_and_challenged_links_refuse_each_others_frames() {
    let mut unchallenged = HostLink::new(binding(), LinkLimits::default(), clock()).unwrap();
    assert_eq!(unchallenged.connection(), Connection::UNCHALLENGED);
    assert_eq!(unchallenged.next_outbound(), None, "no challenge");
    let challenged = encode_frame_on(
        &binding(),
        nonce(1).connection(),
        Sender::Guest,
        1,
        &hello(),
    )
    .unwrap();
    assert_eq!(
        unchallenged.receive(&challenged),
        stale(nonce(1).connection(), Connection::UNCHALLENGED)
    );
}

/// Pins what [`HostLink::new`] still allows: without a challenge, a hello recorded on one
/// unchallenged link is accepted by the next one of the same boot. Callers that need
/// the connection binding use [`HostLink::connect`].
#[test]
fn an_unchallenged_link_still_accepts_a_hello_recorded_on_an_earlier_one() {
    let recorded = [
        encode_frame(&binding(), Sender::Guest, 1, &hello()).unwrap(),
        encode_frame(&binding(), Sender::Guest, 2, &ping(4)).unwrap(),
    ]
    .concat();
    for _connection in 0..2 {
        let mut link = HostLink::new(binding(), LinkLimits::default(), clock()).unwrap();
        let events = link.receive(&recorded);
        let [LinkEvent::Report(report), LinkEvent::Request(GuestRequest::Ping { nonce: 4 })] =
            &events[..]
        else {
            panic!("{events:?}");
        };
        assert_eq!(report.connection(), Connection::UNCHALLENGED);
        let json = serde_json::to_value(report).unwrap();
        assert!(json.get("connection").is_none(), "{json}");
    }
}

#[test]
fn version_1_frames_are_refused_by_name() {
    for mut link in [
        connect(1),
        HostLink::new(binding(), LinkLimits::default(), clock()).unwrap(),
    ] {
        let events = link.receive(&version_1_hello(&binding(), 1));
        let reason = RefusalReason::Framing(FramingRefusal::RetiredVersion { found: 1 });
        assert_eq!(reason.code(), "framing.retired_version");
        assert_eq!(
            events,
            vec![
                LinkEvent::Refused(Refusal {
                    reason: reason.clone(),
                    effect: RefusalEffect::LinkClosed,
                }),
                LinkEvent::Closed(CloseCause::Violation(reason)),
            ]
        );
    }
}

#[test]
fn a_used_up_host_sequence_is_reported_as_a_close_event() {
    // Through take_events, once.
    let (mut link, _guest) = open(1);
    drain(&mut link);
    link.set_last_sent_sequence(u64::MAX - 1);
    link.send(HostMessage::Ping { nonce: 1 }).unwrap();
    let last = read_host(&link.next_outbound().unwrap());
    assert_eq!(last.0.sequence, u64::MAX);
    assert_eq!(link.take_events(), vec![]);
    link.send(HostMessage::Ping { nonce: 2 }).unwrap();
    assert_eq!(link.next_outbound(), None);
    assert_eq!(
        link.phase(),
        &LinkPhase::Closed(CloseCause::SequenceExhausted)
    );
    assert_eq!(link.queued_frames(), 0, "no close frame can be sealed");
    assert_eq!(
        link.take_events(),
        vec![LinkEvent::Closed(CloseCause::SequenceExhausted)]
    );
    assert_eq!(link.take_events(), vec![]);
    assert_eq!(link.tick(), vec![]);

    // Through the next call that returns events, when take_events was not called.
    let (mut link, mut guest) = open(2);
    drain(&mut link);
    link.set_last_sent_sequence(u64::MAX);
    link.send(HostMessage::Ping { nonce: 1 }).unwrap();
    assert_eq!(link.next_outbound(), None);
    assert_eq!(
        link.receive(&guest.frame(&ping(1))),
        vec![
            LinkEvent::Closed(CloseCause::SequenceExhausted),
            LinkEvent::Refused(Refusal {
                reason: RefusalReason::LinkAlreadyClosed,
                effect: RefusalEffect::FrameDropped,
            }),
        ]
    );
    for mut link in [open(3).0, open(4).0] {
        drain(&mut link);
        link.set_last_sent_sequence(u64::MAX);
        link.send(HostMessage::Ping { nonce: 1 }).unwrap();
        assert_eq!(link.next_outbound(), None);
        let events = if link.connection() == nonce(3).connection() {
            link.tick()
        } else {
            link.peer_closed()
        };
        assert_eq!(
            events,
            vec![LinkEvent::Closed(CloseCause::SequenceExhausted)]
        );
        assert_eq!(link.peer_closed(), vec![]);
    }
    assert!(!CloseCause::SequenceExhausted.to_string().is_empty());
}
