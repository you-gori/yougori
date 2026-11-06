//! Tests of the host link against §3.2, VM-P28, VM-P29 and VM-CP-25, and the
//! conformance corpus: its fixture, its replay and its mutations.

use std::sync::Arc;
use std::time::Duration;

use crate::foundation::coordination::VmInstanceId;
use crate::foundation::events::RevocationReason;
use crate::foundation::evidence::SourceClass;
use crate::foundation::ids::{
    digest, AuthorizationEpoch, Digest, ManualClock, MonotonicTime, SandboxBootGeneration,
};

use super::connection::{Connection, ConnectionNonce};
use super::corpus::{
    mutate, operation_of, replay, split_frame, CaseKind, Corpus, CorpusCase, Expectation, Feed,
    HostAction, LastOutcome, LinkExpectation, Mutation, Outcome, Step, CORPUS_FORMAT,
};
use super::fields::{FieldRefusal, FieldWriter, LinkName};
use super::limits::LinkLimits;
use super::link::{
    encode_frame, encode_frame_on, seal, ChannelCloseCause, ClaimedField, CloseCause,
    ConsumeRefusal, HostLink, LinkEvent, LinkPhase, Refusal, RefusalEffect, RefusalReason,
    SendRefusal,
};
use super::messages::{
    AllProbesPassed, CancelCause, CloseReason, FileMode, GrantHandle, GuestRequest, Hello,
    HostMessage, InitReport, InitStage, LinkMessage, OpenRefusalCause, PayloadRefusal,
    ProbeOutcome, ProbeResult, ReportBody, Revoke, Shutdown, StreamId, StreamOpen,
};
use super::report::GuestReport;
use super::secret::{BootstrapSecret, LinkBinding};
use super::sequence::SequenceRefusal;
use super::wire::{
    Channel, FrameHeader, FramingRefusal, Operation, Sender, FRAME_OVERHEAD_BYTES, HEADER_BYTES,
    PROTOCOL_VERSION, RETIRED_PROTOCOL_VERSION, TAG_BYTES,
};

const BOOT: u64 = 7;

fn secret_bytes() -> [u8; 32] {
    let mut bytes = [0u8; 32];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = (index as u8).wrapping_mul(13).wrapping_add(5);
    }
    bytes
}

fn vm() -> VmInstanceId {
    VmInstanceId::new(digest("yougori/link/corpus/v1", &[b"vm"]))
}

fn other_vm() -> VmInstanceId {
    VmInstanceId::new(digest("yougori/link/corpus/v1", &[b"other-vm"]))
}

fn boot() -> SandboxBootGeneration {
    SandboxBootGeneration::new(BOOT)
}

/// The connection nonce of the corpus's challenged links.
fn corpus_nonce() -> ConnectionNonce {
    ConnectionNonce::new(b"corpus-conn-0001").unwrap()
}

fn binding() -> LinkBinding {
    LinkBinding::new(vm(), boot(), BootstrapSecret::new(&secret_bytes()).unwrap())
}

fn name(text: &str) -> LinkName {
    LinkName::new(text).unwrap()
}

fn stream(id: u32) -> StreamId {
    StreamId::new(id).unwrap()
}

fn hello() -> LinkMessage {
    LinkMessage::Hello(Hello {
        guest_version: PROTOCOL_VERSION,
        agent_build: digest("yougori/link/corpus/v1", &[b"agent-build"]),
        claimed_vm: None,
        claimed_boot: None,
    })
}

fn ping(nonce: u64) -> LinkMessage {
    LinkMessage::Ping { nonce }
}

fn egress_open(id: u32) -> LinkMessage {
    LinkMessage::Open {
        stream: stream(id),
        open: StreamOpen::Egress {
            destination: name("api-primary"),
        },
    }
}

fn data(channel: Channel, id: u32, bytes: &[u8]) -> LinkMessage {
    LinkMessage::Data {
        channel,
        stream: stream(id),
        bytes: bytes.to_vec(),
    }
}

/// The guest end of a test link: seals frames with consecutive sequences on one
/// connection.
struct Guest {
    binding: LinkBinding,
    connection: Connection,
    sequence: u64,
}

impl Guest {
    /// The guest of an unchallenged link.
    fn new() -> Self {
        Self::on(Connection::UNCHALLENGED)
    }

    /// The guest of a link challenged with `connection`.
    fn on(connection: Connection) -> Self {
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

    /// A frame with a custom header and payload, sealed with the next sequence.
    fn raw(
        &mut self,
        channel: Channel,
        operation_code: u8,
        stream: u32,
        payload: &[u8],
    ) -> Vec<u8> {
        self.sequence += 1;
        let header = FrameHeader {
            channel,
            operation_code,
            stream,
            sequence: self.sequence,
            boot_generation: BOOT,
            payload_bytes: payload.len() as u32,
            connection: self.connection,
        };
        seal(&self.binding, Sender::Guest, &header, payload)
    }
}

type TestLink = HostLink<Arc<ManualClock>>;

fn new_link(limits: LinkLimits) -> (TestLink, Arc<ManualClock>) {
    let clock = Arc::new(ManualClock::new(MonotonicTime::from_nanos(1_000)));
    let link = HostLink::new(binding(), limits, Arc::clone(&clock)).unwrap();
    (link, clock)
}

fn open_link(limits: LinkLimits) -> (TestLink, Arc<ManualClock>, Guest) {
    let (mut link, clock) = new_link(limits);
    let mut guest = Guest::new();
    let events = link.receive(&guest.frame(&hello()));
    assert!(matches!(&events[..], [LinkEvent::Report(_)]), "{events:?}");
    assert_eq!(link.phase(), &LinkPhase::Open);
    (link, clock, guest)
}

fn file_open(id: u32) -> LinkMessage {
    LinkMessage::Open {
        stream: stream(id),
        open: StreamOpen::File {
            grant: GrantHandle(1),
            entry: name("f"),
            mode: FileMode::Read,
        },
    }
}

/// An open link with a file stream 1 the guest opened and the host accepted: the file
/// channel is flow-controlled as a whole.
fn link_with_file_stream() -> (TestLink, Arc<ManualClock>, Guest) {
    let (mut link, clock, mut guest) = open_link(LinkLimits::default());
    let events = link.receive(&guest.frame(&file_open(1)));
    assert!(matches!(
        &events[..],
        [LinkEvent::Request(GuestRequest::OpenFile { .. })]
    ));
    link.send(HostMessage::Opened {
        channel: Channel::File,
        stream: stream(1),
    })
    .unwrap();
    (link, clock, guest)
}

/// An open link with an egress stream 1 the host accepted.
fn link_with_egress_stream() -> (TestLink, Arc<ManualClock>, Guest) {
    let (mut link, clock, mut guest) = open_link(LinkLimits::default());
    let events = link.receive(&guest.frame(&egress_open(1)));
    assert!(matches!(
        &events[..],
        [LinkEvent::Request(GuestRequest::OpenEgress { .. })]
    ));
    link.send(HostMessage::Opened {
        channel: Channel::Egress,
        stream: stream(1),
    })
    .unwrap();
    (link, clock, guest)
}

fn refusal(events: &[LinkEvent]) -> &Refusal {
    events
        .iter()
        .find_map(|event| match event {
            LinkEvent::Refused(refusal) => Some(refusal),
            _ => None,
        })
        .unwrap_or_else(|| panic!("no refusal in {events:?}"))
}

fn assert_refused(events: &[LinkEvent], reason: RefusalReason, effect: RefusalEffect) {
    assert_eq!(refusal(events), &Refusal { reason, effect }, "{events:?}");
}

fn head(frame: &[u8]) -> [u8; HEADER_BYTES] {
    frame[..HEADER_BYTES].try_into().unwrap()
}

fn decode_host_frame(binding: &LinkBinding, frame: &[u8]) -> (FrameHeader, LinkMessage) {
    let parts = split_frame(frame).unwrap();
    let header_bytes = head(frame);
    assert!(binding.verify(Sender::Host, &header_bytes, &parts.payload, &parts.tag));
    assert_eq!(parts.header.boot_generation, BOOT);
    let operation = Operation::decode(parts.header.channel, parts.header.operation_code).unwrap();
    let message = LinkMessage::decode(
        parts.header.channel,
        operation,
        parts.header.stream,
        &parts.payload,
        65_472,
    )
    .unwrap();
    (parts.header, message)
}

fn drain(link: &mut TestLink) -> Vec<(FrameHeader, LinkMessage)> {
    let binding = binding();
    let mut frames = Vec::new();
    while let Some(frame) = link.next_outbound() {
        frames.push(decode_host_frame(&binding, &frame));
    }
    frames
}

// ---------------------------------------------------------------------------------------
// §3.2: one versioned protocol, binding, handshake
// ---------------------------------------------------------------------------------------

#[test]
fn hello_opens_the_link_and_welcome_goes_out_first() {
    let (mut link, _clock) = new_link(LinkLimits::default());
    assert_eq!(link.phase(), &LinkPhase::AwaitingHello);
    let mut guest = Guest::new();
    let events = link.receive(&guest.frame(&hello()));
    match &events[..] {
        [LinkEvent::Report(report)] => {
            assert_eq!(report.source(), SourceClass::GuestReport);
            assert_eq!(report.vm(), vm());
            assert_eq!(report.boot(), boot());
            assert_eq!(report.sequence(), 1);
            assert!(matches!(report.body(), ReportBody::Hello(_)));
        }
        other => panic!("{other:?}"),
    }
    let frames = drain(&mut link);
    assert_eq!(frames.len(), 1);
    assert_eq!(frames[0].0.sequence, 1);
    assert!(matches!(
        frames[0].1,
        LinkMessage::Welcome(terms) if terms.version == PROTOCOL_VERSION
            && terms.max_frame_bytes == 65_552
            && terms.idle_timeout_seconds == 60
    ));
}

#[test]
fn frames_before_hello_are_refused_and_a_second_hello_too() {
    let (mut link, _clock) = new_link(LinkLimits::default());
    let mut guest = Guest::new();
    let events = link.receive(&guest.frame(&ping(1)));
    assert_refused(
        &events,
        RefusalReason::HandshakeIncomplete {
            operation: Operation::Ping,
        },
        RefusalEffect::FrameDropped,
    );
    assert_eq!(link.phase(), &LinkPhase::AwaitingHello);
    assert!(matches!(
        &link.receive(&guest.frame(&hello()))[..],
        [LinkEvent::Report(_)]
    ));
    let events = link.receive(&guest.frame(&hello()));
    assert_refused(
        &events,
        RefusalReason::HandshakeRepeated,
        RefusalEffect::FrameDropped,
    );
    assert_eq!(link.refusals(), 2);
}

#[test]
fn another_guest_version_closes_the_link() {
    for version in [RETIRED_PROTOCOL_VERSION, PROTOCOL_VERSION + 1] {
        let (mut link, _clock) = new_link(LinkLimits::default());
        let mut guest = Guest::new();
        let events = link.receive(&guest.frame(&LinkMessage::Hello(Hello {
            guest_version: version,
            agent_build: digest("yougori/link/corpus/v1", &[b"agent-build"]),
            claimed_vm: None,
            claimed_boot: None,
        })));
        assert_refused(
            &events,
            RefusalReason::UnsupportedGuestVersion { version },
            RefusalEffect::LinkClosed,
        );
        assert!(link.is_closed());
    }
}

#[test]
fn the_host_sends_only_urgent_control_before_hello() {
    let (mut link, _clock) = new_link(LinkLimits::default());
    assert_eq!(
        link.send(HostMessage::Ping { nonce: 1 }),
        Err(SendRefusal::HandshakeIncomplete)
    );
    assert_eq!(
        link.send(HostMessage::OpenTerminal {
            stream: stream(2),
            columns: 80,
            rows: 24
        }),
        Err(SendRefusal::HandshakeIncomplete)
    );
    link.send(HostMessage::Revoke(Revoke {
        reason: RevocationReason::SecurityEvent,
        authorization_epoch: AuthorizationEpoch::new(2),
    }))
    .unwrap();
    link.send(HostMessage::Shutdown(Shutdown { grace_seconds: 5 }))
        .unwrap();
    let frames = drain(&mut link);
    assert!(matches!(frames[0].1, LinkMessage::Revoke(_)));
    assert!(matches!(frames[1].1, LinkMessage::Shutdown(_)));
}

// ---------------------------------------------------------------------------------------
// §3.2 and VM-R49: host-authoritative identity, generation and sequence binding
// ---------------------------------------------------------------------------------------

#[test]
fn an_unauthenticated_frame_closes_the_link() {
    let (mut link, _clock) = new_link(LinkLimits::default());
    let mut guest = Guest::new();
    let mut frame = guest.frame(&hello());
    let last = frame.len() - 1;
    frame[last] ^= 0x01;
    let events = link.receive(&frame);
    assert_eq!(
        events,
        vec![
            LinkEvent::Refused(Refusal {
                reason: RefusalReason::Unauthenticated,
                effect: RefusalEffect::LinkClosed
            }),
            LinkEvent::Closed(CloseCause::Violation(RefusalReason::Unauthenticated)),
        ]
    );
    assert!(link.is_closed());
    assert_eq!(
        link.receive(b"more"),
        vec![LinkEvent::Refused(Refusal {
            reason: RefusalReason::LinkAlreadyClosed,
            effect: RefusalEffect::FrameDropped
        })]
    );
}

#[test]
fn a_frame_from_another_instances_secret_is_unauthenticated() {
    let (mut link, _clock) = new_link(LinkLimits::default());
    let mut other_secret = secret_bytes();
    other_secret[0] ^= 0xff;
    let other = LinkBinding::new(vm(), boot(), BootstrapSecret::new(&other_secret).unwrap());
    let frame = encode_frame(&other, Sender::Guest, 1, &hello()).unwrap();
    assert_eq!(
        refusal(&link.receive(&frame)).reason,
        RefusalReason::Unauthenticated
    );
    let host_keyed = encode_frame(&binding(), Sender::Host, 1, &hello()).unwrap();
    let (mut link, _clock) = new_link(LinkLimits::default());
    assert_eq!(
        refusal(&link.receive(&host_keyed)).reason,
        RefusalReason::Unauthenticated
    );
}

#[test]
fn a_stale_or_future_generation_is_refused() {
    for generation in [BOOT - 1, BOOT + 1] {
        let (mut link, _clock) = new_link(LinkLimits::default());
        let stale = LinkBinding::new(
            vm(),
            SandboxBootGeneration::new(generation),
            BootstrapSecret::new(&secret_bytes()).unwrap(),
        );
        let frame = encode_frame(&stale, Sender::Guest, 1, &hello()).unwrap();
        let events = link.receive(&frame);
        assert_eq!(
            refusal(&events).reason,
            RefusalReason::Unauthenticated,
            "a generation change changes the key"
        );
    }
    let (mut link, _clock) = new_link(LinkLimits::default());
    let payload = hello().encode_payload().unwrap();
    let header = FrameHeader {
        channel: Channel::Control,
        operation_code: Operation::Hello.code(),
        stream: 0,
        sequence: 1,
        boot_generation: BOOT - 1,
        payload_bytes: payload.len() as u32,
        connection: Connection::UNCHALLENGED,
    };
    let frame = seal(&binding(), Sender::Guest, &header, &payload);
    let events = link.receive(&frame);
    assert_refused(
        &events,
        RefusalReason::StaleGeneration {
            frame: BOOT - 1,
            bound: BOOT,
        },
        RefusalEffect::LinkClosed,
    );
    assert!(link.is_closed());
}

#[test]
fn a_replayed_or_reordered_sequence_closes_the_link() {
    let (mut link, _clock, mut guest) = open_link(LinkLimits::default());
    let frame = guest.frame(&ping(1));
    assert!(matches!(&link.receive(&frame)[..], [LinkEvent::Request(_)]));
    let events = link.receive(&frame);
    assert_refused(
        &events,
        RefusalReason::Sequence(SequenceRefusal::Replayed {
            sequence: 2,
            last_accepted: 2,
        }),
        RefusalEffect::LinkClosed,
    );
    assert!(link.is_closed());

    let (mut link, _clock, mut guest) = open_link(LinkLimits::default());
    guest.sequence += 1;
    let events = link.receive(&guest.frame(&ping(1)));
    assert_refused(
        &events,
        RefusalReason::Sequence(SequenceRefusal::Reordered {
            sequence: 3,
            expected: 2,
        }),
        RefusalEffect::LinkClosed,
    );

    let (mut link, _clock, mut guest) = open_link(LinkLimits::default());
    let later = guest.frame(&ping(1));
    let earlier = guest.frame(&ping(2));
    let events = link.receive(&[earlier, later].concat());
    assert!(matches!(
        refusal(&events).reason,
        RefusalReason::Sequence(SequenceRefusal::Reordered { .. })
    ));
}

#[test]
fn a_guest_supplied_identity_is_never_identity_and_is_refused_where_it_disagrees() {
    let (mut link, _clock) = new_link(LinkLimits::default());
    let mut guest = Guest::new();
    let events = link.receive(&guest.frame(&LinkMessage::Hello(Hello {
        guest_version: PROTOCOL_VERSION,
        agent_build: digest("yougori/link/corpus/v1", &[b"agent-build"]),
        claimed_vm: Some(other_vm().digest()),
        claimed_boot: Some(BOOT),
    })));
    assert_refused(
        &events,
        RefusalReason::ClaimedIdentityDisagrees {
            field: ClaimedField::Vm,
        },
        RefusalEffect::LinkClosed,
    );

    let (mut link, _clock) = new_link(LinkLimits::default());
    let mut guest = Guest::new();
    let events = link.receive(&guest.frame(&LinkMessage::Hello(Hello {
        guest_version: PROTOCOL_VERSION,
        agent_build: digest("yougori/link/corpus/v1", &[b"agent-build"]),
        claimed_vm: Some(vm().digest()),
        claimed_boot: Some(BOOT + 1),
    })));
    assert_refused(
        &events,
        RefusalReason::ClaimedIdentityDisagrees {
            field: ClaimedField::Boot,
        },
        RefusalEffect::LinkClosed,
    );

    let (mut link, _clock, mut guest) = open_link(LinkLimits::default());
    let events = link.receive(&guest.frame(&LinkMessage::InitReport(InitReport {
        stage: InitStage::Agent,
        outcome: ProbeOutcome::Passed,
        detail: String::new(),
        claimed_vm: Some(other_vm().digest()),
    })));
    assert!(matches!(
        refusal(&events).reason,
        RefusalReason::ClaimedIdentityDisagrees { .. }
    ));
    assert!(link.is_closed());

    let (mut link, _clock, mut guest) = open_link(LinkLimits::default());
    let events = link.receive(&guest.frame(&LinkMessage::InitReport(InitReport {
        stage: InitStage::Agent,
        outcome: ProbeOutcome::Passed,
        detail: String::new(),
        claimed_vm: Some(vm().digest()),
    })));
    match &events[..] {
        [LinkEvent::Report(report)] => {
            assert_eq!(report.vm(), link.binding().vm());
            assert_eq!(report.boot(), link.binding().boot());
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn the_secret_never_appears_in_debug_or_serde_of_the_link_or_its_events() {
    let (mut link, _clock, mut guest) = open_link(LinkLimits::default());
    let events = link.receive(&guest.frame(&LinkMessage::AllProbesPassed(AllProbesPassed {
        probe_count: 3,
    })));
    let hex = hex::encode(secret_bytes());
    let texts = [
        format!("{link:?}"),
        format!("{link:#?}"),
        format!("{:?}", link.binding()),
        serde_json::to_string(link.binding()).unwrap(),
        format!("{events:?}"),
        serde_json::to_string(&events).unwrap(),
        serde_json::to_string(link.phase()).unwrap(),
    ];
    for text in texts {
        assert!(!text.contains(&hex), "{text}");
        assert!(!text.contains(&hex[..12]), "{text}");
        assert!(!text.contains(&hex.to_uppercase()[..12]), "{text}");
    }
    assert!(format!("{link:?}").contains("not shown"));
}

// ---------------------------------------------------------------------------------------
// VM-P29 and VM-CP-25: guest reports stay guest reports
// ---------------------------------------------------------------------------------------

#[test]
fn forged_init_and_probe_reports_are_guest_reports_and_satisfy_no_host_only_requirement() {
    let (mut link, _clock, mut guest) = open_link(LinkLimits::default());
    let reports = [
        LinkMessage::InitReport(InitReport {
            stage: InitStage::Restrictions,
            outcome: ProbeOutcome::Passed,
            detail: "seccomp applied".to_owned(),
            claimed_vm: None,
        }),
        LinkMessage::ProbeResult(ProbeResult {
            probe: name("hypervisor-confinement"),
            outcome: ProbeOutcome::Passed,
            detail: "root says yes".to_owned(),
        }),
        LinkMessage::AllProbesPassed(AllProbesPassed { probe_count: 40 }),
    ];
    for (index, message) in reports.iter().enumerate() {
        let events = link.receive(&guest.frame(message));
        match &events[..] {
            [LinkEvent::Report(report)] => {
                assert_eq!(report.source(), SourceClass::GuestReport);
                assert_eq!(GuestReport::SOURCE, SourceClass::GuestReport);
                assert!(!report.satisfies(SourceClass::HostProbe));
                assert!(!report.satisfies(SourceClass::ProviderApi));
                assert!(report.satisfies(SourceClass::GuestReport));
                assert_eq!(report.sequence(), index as u64 + 2);
                let json = serde_json::to_value(report).unwrap();
                assert_eq!(json["source"], "guest_report");
                assert_eq!(json["vm"], serde_json::json!(vm()));
                assert!(json.get("host_observed").is_none());
            }
            other => panic!("{other:?}"),
        }
    }
    let exit = {
        link.send(HostMessage::OpenTerminal {
            stream: stream(2),
            columns: 80,
            rows: 24,
        })
        .unwrap();
        link.receive(&guest.frame(&LinkMessage::Opened {
            channel: Channel::Terminal,
            stream: stream(2),
        }));
        link.receive(&guest.frame(&LinkMessage::Exit {
            stream: stream(2),
            code: 0,
        }))
    };
    assert!(matches!(
        &exit[..],
        [LinkEvent::Report(report)] if report.source() == SourceClass::GuestReport
            && matches!(report.body(), ReportBody::TerminalExit { code: 0, .. })
    ));
}

#[test]
fn the_guest_report_type_cannot_be_deserialized_or_given_another_source() {
    let (mut link, _clock, mut guest) = open_link(LinkLimits::default());
    let events = link.receive(&guest.frame(&LinkMessage::AllProbesPassed(AllProbesPassed {
        probe_count: 1,
    })));
    let LinkEvent::Report(report) = &events[0] else {
        panic!("{events:?}");
    };
    let mut json = serde_json::to_value(report).unwrap();
    json["source"] = serde_json::json!("host_probe");
    // There is no Deserialize for GuestReport, so a rewritten record cannot come back as
    // one; the only way to a GuestReport is a frame the bound guest authenticated.
    assert_eq!(report.source(), SourceClass::GuestReport);
    assert!(!SourceClass::GuestReport.satisfies(SourceClass::HostProbe));
}

// ---------------------------------------------------------------------------------------
// §3.2 and §2.6: typed operations, directionality, unknown operations, no host actions
// ---------------------------------------------------------------------------------------

#[test]
fn every_host_only_or_unknown_operation_from_the_guest_is_refused() {
    let mut limits = LinkLimits::default();
    limits.max_refusals = 10_000;
    let (mut link, _clock, mut guest) = open_link(limits);
    let mut checked = 0;
    for channel in Channel::ALL {
        for code in 0..=255u8 {
            let operation = Operation::decode(channel, code);
            let guest_allowed = operation.is_some_and(|operation| {
                operation
                    .direction(channel)
                    .is_some_and(|direction| direction.allows(Sender::Guest))
            });
            if guest_allowed {
                continue;
            }
            let stream = match operation.map(Operation::stream_use) {
                Some(super::wire::StreamUse::Required) => 1,
                _ => 0,
            };
            let events = link.receive(&guest.raw(channel, code, stream, &[]));
            let expected = match operation {
                Some(operation) => RefusalReason::WrongDirection { channel, operation },
                None => RefusalReason::UnknownOperation { channel, code },
            };
            assert_refused(&events, expected, RefusalEffect::FrameDropped);
            checked += 1;
        }
    }
    assert!(checked > 1_200);
    assert_eq!(link.phase(), &LinkPhase::Open);
    assert_eq!(link.refusals(), checked);
}

#[test]
fn guest_requests_never_carry_paths_executables_or_endpoints() {
    let (mut link, _clock, mut guest) = open_link(LinkLimits::default());
    for text in [
        "../../etc/shadow",
        "/usr/bin/sh",
        "C:\\Windows\\cmd.exe",
        "https://169.254.169.254/",
        "10.0.0.1:22",
    ] {
        let payload = FieldWriter::new().text(1, text).unwrap().finish();
        let events = link.receive(&guest.raw(Channel::Egress, Operation::Open.code(), 1, &payload));
        assert!(matches!(
            refusal(&events).reason,
            RefusalReason::Payload(PayloadRefusal::Field(FieldRefusal::NotName { tag: 1, .. }))
        ));
        let payload = FieldWriter::new()
            .u64(1, 9)
            .text(2, text)
            .unwrap()
            .u8(3, FileMode::Read.code())
            .finish();
        let events = link.receive(&guest.raw(Channel::File, Operation::Open.code(), 1, &payload));
        assert!(matches!(
            refusal(&events).reason,
            RefusalReason::Payload(PayloadRefusal::Field(FieldRefusal::NotName { tag: 2, .. }))
        ));
    }
    let events = link.receive(&guest.frame(&LinkMessage::Open {
        stream: stream(1),
        open: StreamOpen::File {
            grant: GrantHandle(9),
            entry: name("report.txt"),
            mode: FileMode::Read,
        },
    }));
    match &events[..] {
        [LinkEvent::Request(request)] => {
            let json = serde_json::to_string(request).unwrap();
            assert!(!json.contains('/'));
            assert!(!json.contains('\\'));
            assert!(matches!(
                request,
                GuestRequest::OpenFile {
                    grant: GrantHandle(9),
                    ..
                }
            ));
        }
        other => panic!("{other:?}"),
    }
}

// ---------------------------------------------------------------------------------------
// VM-P28: parser boundary cases, each bounded with a typed reason
// ---------------------------------------------------------------------------------------

#[test]
fn an_oversized_frame_is_refused_before_its_payload_is_buffered() {
    let (mut link, _clock, mut guest) = open_link(LinkLimits::default());
    let mut frame = guest.frame(&ping(1));
    frame[28..32].copy_from_slice(&65_473u32.to_be_bytes());
    let events = link.receive(&frame);
    assert_refused(
        &events,
        RefusalReason::Framing(FramingRefusal::Oversized {
            frame_bytes: 65_473 + FRAME_OVERHEAD_BYTES as u64,
            max_frame_bytes: 65_552,
        }),
        RefusalEffect::LinkClosed,
    );
    assert_eq!(link.decoder_buffered_bytes(), 0);
    assert!(link.is_closed());
}

#[test]
fn a_message_above_its_channels_limit_is_refused_even_when_the_frame_fits() {
    let (mut link, _clock, mut guest) = open_link(LinkLimits::default());
    let payload = FieldWriter::new()
        .u64(1, 1)
        .bytes(2, &vec![0u8; 5_000])
        .unwrap()
        .finish();
    let events = link.receive(&guest.raw(Channel::Control, Operation::Ping.code(), 0, &payload));
    assert_refused(
        &events,
        RefusalReason::MessageTooLarge {
            channel: Channel::Control,
            payload_bytes: payload.len(),
            max_message_bytes: 4_096,
        },
        RefusalEffect::FrameDropped,
    );
    assert_eq!(link.phase(), &LinkPhase::Open);
}

#[test]
fn a_truncated_frame_is_refused_when_the_peer_disconnects() {
    let (mut link, _clock, mut guest) = open_link(LinkLimits::default());
    let frame = guest.frame(&ping(1));
    assert_eq!(link.receive(&frame[..frame.len() - 5]), vec![]);
    assert_eq!(link.decoder_buffered_bytes(), frame.len() - 5);
    let events = link.peer_closed();
    assert_refused(
        &events,
        RefusalReason::Framing(FramingRefusal::Truncated {
            have_bytes: frame.len() - 5,
            need_bytes: frame.len(),
        }),
        RefusalEffect::LinkClosed,
    );
    assert_eq!(link.decoder_buffered_bytes(), 0);

    let (mut link, _clock, _guest) = open_link(LinkLimits::default());
    assert_eq!(
        link.peer_closed(),
        vec![LinkEvent::Closed(CloseCause::PeerDisconnected)]
    );
    assert_eq!(link.peer_closed(), vec![]);
}

#[test]
fn a_slow_peer_one_byte_at_a_time_is_decoded_identically_and_stays_bounded() {
    let (mut whole, _clock, mut guest) = open_link(LinkLimits::default());
    let frames = [
        guest.frame(&ping(1)),
        guest.frame(&egress_open(1)),
        guest.frame(&LinkMessage::ProbeResult(ProbeResult {
            probe: name("p1"),
            outcome: ProbeOutcome::Skipped,
            detail: "x".repeat(200),
        })),
    ]
    .concat();
    let all = whole.receive(&frames);
    let (mut slow, _clock, _guest) = open_link(LinkLimits::default());
    let mut collected = Vec::new();
    let mut peak = 0;
    for byte in &frames {
        collected.extend(slow.receive(std::slice::from_ref(byte)));
        peak = peak.max(slow.decoder_buffered_bytes());
    }
    assert_eq!(all.len(), 3);
    assert_eq!(strip_times(&all), strip_times(&collected));
    assert!(peak < frames.len());
    assert!(peak <= 65_536);
}

fn strip_times(events: &[LinkEvent]) -> Vec<String> {
    events
        .iter()
        .map(|event| {
            let mut json = serde_json::to_value(event).unwrap();
            if let Some(received_at) = json.get_mut("received_at") {
                *received_at = serde_json::Value::Null;
            }
            json.to_string()
        })
        .collect()
}

#[test]
fn a_slow_peer_that_never_completes_a_frame_times_out() {
    let (mut link, clock, mut guest) = open_link(LinkLimits::default());
    let frame = guest.frame(&ping(1));
    link.receive(&frame[..10]);
    clock.advance(Duration::from_secs(5));
    assert_eq!(link.tick(), vec![]);
    clock.advance(Duration::from_nanos(1));
    assert_eq!(
        link.tick(),
        vec![LinkEvent::Closed(CloseCause::FrameTimedOut)]
    );
    assert!(link.is_closed());
}

#[test]
fn nested_and_recursive_payloads_are_refused_without_recursion() {
    let (mut link, _clock, mut guest) = open_link(LinkLimits::default());
    let mut payload = ping(1).encode_payload().unwrap();
    while payload.len() + 3 <= 4_096 {
        payload = FieldWriter::new().bytes(1, &payload).unwrap().finish();
    }
    let events = link.receive(&guest.raw(Channel::Control, Operation::Ping.code(), 0, &payload));
    assert!(matches!(
        refusal(&events).reason,
        RefusalReason::Payload(PayloadRefusal::Field(FieldRefusal::WrongLength {
            tag: 1,
            ..
        }))
    ));
    let inner = encode_frame(&binding(), Sender::Guest, 99, &ping(2)).unwrap();
    let frame_in_frame = guest.raw(Channel::Control, Operation::Ping.code(), 0, &inner);
    let events = link.receive(&frame_in_frame);
    assert!(matches!(
        refusal(&events).reason,
        RefusalReason::Payload(PayloadRefusal::Field(_))
    ));
    assert_eq!(link.phase(), &LinkPhase::Open);
}

#[test]
fn duplicate_unknown_and_missing_fields_are_refused() {
    let (mut link, _clock, mut guest) = open_link(LinkLimits::default());
    let duplicate = FieldWriter::new().u64(1, 1).u64(1, 2).finish();
    let events = link.receive(&guest.raw(Channel::Control, Operation::Ping.code(), 0, &duplicate));
    assert_eq!(
        refusal(&events).reason,
        RefusalReason::Payload(PayloadRefusal::Field(FieldRefusal::DuplicateField {
            tag: 1
        }))
    );
    let unknown = FieldWriter::new().u64(1, 1).u8(2, 0).finish();
    let events = link.receive(&guest.raw(Channel::Control, Operation::Ping.code(), 0, &unknown));
    assert_eq!(
        refusal(&events).reason,
        RefusalReason::Payload(PayloadRefusal::Field(FieldRefusal::UnknownField { tag: 2 }))
    );
    let events = link.receive(&guest.raw(Channel::Control, Operation::Ping.code(), 0, &[]));
    assert_eq!(
        refusal(&events).reason,
        RefusalReason::Payload(PayloadRefusal::Field(FieldRefusal::MissingField { tag: 1 }))
    );
    assert_eq!(link.refusals(), 3);
}

#[test]
fn invalid_state_transitions_on_streams_are_refused() {
    let (mut link, _clock, mut guest) = open_link(LinkLimits::default());
    let events = link.receive(&guest.frame(&data(Channel::Egress, 1, b"x")));
    assert_eq!(
        refusal(&events).reason,
        RefusalReason::StreamNotOpen {
            channel: Channel::Egress,
            stream: stream(1)
        }
    );
    let events = link.receive(&guest.frame(&egress_open(2)));
    assert_eq!(
        refusal(&events).reason,
        RefusalReason::StreamParity { stream: stream(2) }
    );
    assert!(matches!(
        &link.receive(&guest.frame(&egress_open(3)))[..],
        [LinkEvent::Request(_)]
    ));
    let events = link.receive(&guest.frame(&egress_open(1)));
    assert_eq!(
        refusal(&events).reason,
        RefusalReason::StreamIdNotIncreasing {
            stream: stream(1),
            highest: 3
        }
    );
    let events = link.receive(&guest.frame(&data(Channel::Egress, 3, b"early")));
    assert_eq!(
        refusal(&events).reason,
        RefusalReason::StreamNotOpen {
            channel: Channel::Egress,
            stream: stream(3)
        }
    );
    let events = link.receive(&guest.frame(&LinkMessage::Opened {
        channel: Channel::Egress,
        stream: stream(3),
    }));
    assert_eq!(
        refusal(&events).reason,
        RefusalReason::WrongDirection {
            channel: Channel::Egress,
            operation: Operation::Opened
        },
        "on egress only the host answers an open"
    );
    link.receive(&guest.frame(&LinkMessage::Open {
        stream: stream(1),
        open: StreamOpen::File {
            grant: GrantHandle(1),
            entry: name("a"),
            mode: FileMode::Read,
        },
    }));
    let events = link.receive(&guest.frame(&LinkMessage::Opened {
        channel: Channel::File,
        stream: stream(1),
    }));
    assert_eq!(
        refusal(&events).reason,
        RefusalReason::StreamNotOpening {
            channel: Channel::File,
            stream: stream(1)
        },
        "the guest cannot answer its own open"
    );
    assert_eq!(
        link.send(HostMessage::Opened {
            channel: Channel::Egress,
            stream: stream(5)
        }),
        Err(SendRefusal::StreamNotOpen {
            channel: Channel::Egress,
            stream: stream(5)
        })
    );
    link.send(HostMessage::Opened {
        channel: Channel::Egress,
        stream: stream(3),
    })
    .unwrap();
    assert_eq!(
        link.send(HostMessage::Opened {
            channel: Channel::Egress,
            stream: stream(3)
        }),
        Err(SendRefusal::StreamNotOpening {
            channel: Channel::Egress,
            stream: stream(3)
        })
    );
    assert!(matches!(
        &link.receive(&guest.frame(&data(Channel::Egress, 3, b"ok")))[..],
        [LinkEvent::Request(GuestRequest::Data { .. })]
    ));
    assert_eq!(link.channel(Channel::Egress).streams, 1);
    assert_eq!(link.channel(Channel::File).streams, 1);
    assert_eq!(link.phase(), &LinkPhase::Open);
}

#[test]
fn the_stream_quota_of_a_channel_is_enforced() {
    let mut limits = LinkLimits::default();
    limits.egress.max_streams = 2;
    let (mut link, _clock, mut guest) = open_link(limits);
    link.receive(&guest.frame(&egress_open(1)));
    link.receive(&guest.frame(&egress_open(3)));
    let events = link.receive(&guest.frame(&egress_open(5)));
    assert_eq!(
        refusal(&events).reason,
        RefusalReason::StreamQuotaExceeded {
            channel: Channel::Egress,
            max_streams: 2
        }
    );
    assert_eq!(link.channel(Channel::Egress).streams, 2);
    assert_eq!(link.channel(Channel::File).streams, 0);
    assert!(matches!(
        &link.receive(&guest.frame(&LinkMessage::Open {
            stream: stream(1),
            open: StreamOpen::File {
                grant: GrantHandle(1),
                entry: name("a"),
                mode: FileMode::Read
            }
        }))[..],
        [LinkEvent::Request(_)]
    ));
    limits.terminal.max_streams = 1;
    let (mut link, _clock, _guest) = open_link(limits);
    link.send(HostMessage::OpenTerminal {
        stream: stream(2),
        columns: 1,
        rows: 1,
    })
    .unwrap();
    assert_eq!(
        link.send(HostMessage::OpenTerminal {
            stream: stream(4),
            columns: 1,
            rows: 1
        }),
        Err(SendRefusal::StreamQuotaExceeded {
            channel: Channel::Terminal,
            max_streams: 1
        })
    );
    assert_eq!(
        link.send(HostMessage::OpenTerminal {
            stream: stream(3),
            columns: 1,
            rows: 1
        }),
        Err(SendRefusal::StreamParity { stream: stream(3) })
    );
}

#[test]
fn the_refusal_budget_closes_the_link() {
    let mut limits = LinkLimits::default();
    limits.max_refusals = 3;
    let (mut link, _clock, mut guest) = open_link(limits);
    for _ in 0..2 {
        let events = link.receive(&guest.frame(&hello()));
        assert_eq!(refusal(&events).effect, RefusalEffect::FrameDropped);
    }
    let events = link.receive(&guest.frame(&hello()));
    assert_eq!(
        events,
        vec![
            LinkEvent::Refused(Refusal {
                reason: RefusalReason::HandshakeRepeated,
                effect: RefusalEffect::LinkClosed
            }),
            LinkEvent::Closed(CloseCause::RefusalBudgetExhausted { max_refusals: 3 }),
        ]
    );
    assert!(link.is_closed());
}

// ---------------------------------------------------------------------------------------
// §3.2: cancellation, timeout, backpressure and half-close
// ---------------------------------------------------------------------------------------

#[test]
fn a_guest_cancel_drops_the_stream_and_its_queued_host_frames() {
    let (mut link, _clock, mut guest) = link_with_egress_stream();
    while link.next_outbound().is_some() {}
    link.send(HostMessage::Data {
        channel: Channel::Egress,
        stream: stream(1),
        bytes: b"queued".to_vec(),
    })
    .unwrap();
    assert_eq!(link.channel(Channel::Egress).queued_frames, 1);
    let events = link.receive(&guest.frame(&LinkMessage::Cancel {
        channel: Channel::Egress,
        stream: stream(1),
        cause: CancelCause::Requested,
    }));
    assert!(matches!(
        &events[..],
        [LinkEvent::Request(GuestRequest::Cancel { .. })]
    ));
    assert_eq!(link.channel(Channel::Egress).streams, 0);
    assert_eq!(link.channel(Channel::Egress).queued_frames, 0);
    let events = link.receive(&guest.frame(&data(Channel::Egress, 1, b"late")));
    assert_refused(
        &events,
        RefusalReason::StreamCancelled {
            channel: Channel::Egress,
            stream: stream(1),
        },
        RefusalEffect::FrameDropped,
    );
    assert_eq!(
        link.refusals(),
        0,
        "in-flight frames of a cancelled stream are not charged"
    );
    let events = link.receive(&guest.frame(&egress_open(1)));
    assert!(matches!(
        refusal(&events).reason,
        RefusalReason::StreamIdNotIncreasing { .. }
    ));
}

#[test]
fn a_host_cancel_is_sent_and_late_guest_data_is_refused_without_charge() {
    let (mut link, _clock, mut guest) = link_with_egress_stream();
    link.send(HostMessage::Cancel {
        channel: Channel::Egress,
        stream: stream(1),
        cause: CancelCause::Revoked,
    })
    .unwrap();
    assert_eq!(link.channel(Channel::Egress).streams, 0);
    let frames = drain(&mut link);
    assert!(frames.iter().any(|(_, message)| matches!(
        message,
        LinkMessage::Cancel {
            cause: CancelCause::Revoked,
            ..
        }
    )));
    let events = link.receive(&guest.frame(&data(Channel::Egress, 1, b"late")));
    assert_eq!(
        refusal(&events).reason,
        RefusalReason::StreamCancelled {
            channel: Channel::Egress,
            stream: stream(1)
        }
    );
    assert_eq!(link.refusals(), 0);
    assert_eq!(
        link.send(HostMessage::Cancel {
            channel: Channel::Egress,
            stream: stream(1),
            cause: CancelCause::Requested
        }),
        Err(SendRefusal::StreamNotOpen {
            channel: Channel::Egress,
            stream: stream(1)
        })
    );
}

#[test]
fn the_cancelled_set_is_bounded_by_the_stream_quota() {
    let mut limits = LinkLimits::default();
    limits.egress.max_streams = 2;
    let (mut link, _clock, mut guest) = open_link(limits);
    for id in [1, 3, 5] {
        link.receive(&guest.frame(&egress_open(id)));
        link.receive(&guest.frame(&LinkMessage::Cancel {
            channel: Channel::Egress,
            stream: stream(id),
            cause: CancelCause::Requested,
        }));
    }
    let events = link.receive(&guest.frame(&data(Channel::Egress, 1, b"x")));
    assert_eq!(
        refusal(&events).reason,
        RefusalReason::StreamNotOpen {
            channel: Channel::Egress,
            stream: stream(1)
        }
    );
    let events = link.receive(&guest.frame(&data(Channel::Egress, 5, b"x")));
    assert_eq!(
        refusal(&events).reason,
        RefusalReason::StreamCancelled {
            channel: Channel::Egress,
            stream: stream(5)
        }
    );
}

#[test]
fn handshake_idle_and_open_timeouts_fire_only_after_their_durations() {
    let (mut link, clock) = new_link(LinkLimits::default());
    clock.advance(Duration::from_secs(10));
    assert_eq!(link.tick(), vec![]);
    clock.advance(Duration::from_nanos(1));
    assert_eq!(
        link.tick(),
        vec![LinkEvent::Closed(CloseCause::HandshakeTimedOut)]
    );
    assert_eq!(link.tick(), vec![]);

    let (mut link, clock, mut guest) = open_link(LinkLimits::default());
    clock.advance(Duration::from_secs(59));
    link.receive(&guest.frame(&ping(1)));
    clock.advance(Duration::from_secs(60));
    assert_eq!(link.tick(), vec![]);
    clock.advance(Duration::from_nanos(1));
    assert_eq!(
        link.tick(),
        vec![LinkEvent::Closed(CloseCause::IdleTimedOut)]
    );

    let (mut link, clock, mut guest) = open_link(LinkLimits::default());
    link.receive(&guest.frame(&egress_open(1)));
    link.send(HostMessage::OpenTerminal {
        stream: stream(2),
        columns: 80,
        rows: 24,
    })
    .unwrap();
    clock.advance(Duration::from_secs(30));
    assert_eq!(link.tick(), vec![]);
    clock.advance(Duration::from_secs(1));
    link.receive(&guest.frame(&ping(1)));
    let events = link.tick();
    assert_eq!(
        events,
        vec![
            LinkEvent::StreamTimedOut {
                channel: Channel::Terminal,
                stream: stream(2),
                cancel_sent: true
            },
            LinkEvent::StreamTimedOut {
                channel: Channel::Egress,
                stream: stream(1),
                cancel_sent: true
            },
        ]
    );
    assert_eq!(link.channel(Channel::Egress).streams, 0);
    let frames = drain(&mut link);
    let cancels = frames
        .iter()
        .filter(|(_, message)| {
            matches!(
                message,
                LinkMessage::Cancel {
                    cause: CancelCause::TimedOut,
                    ..
                }
            )
        })
        .count();
    assert_eq!(cancels, 2);
    let events = link.receive(&guest.frame(&data(Channel::Egress, 1, b"x")));
    assert!(matches!(
        refusal(&events).reason,
        RefusalReason::StreamCancelled { .. }
    ));
}

#[test]
fn guest_data_beyond_the_receive_window_closes_the_channel_and_consume_restores_credit() {
    let mut limits = LinkLimits::default();
    limits.file.max_message_bytes = 100;
    limits.file.max_buffered_bytes = 150;
    let (mut link, _clock, mut guest) = open_link(limits);
    link.receive(&guest.frame(&file_open(1)));
    link.send(HostMessage::Opened {
        channel: Channel::File,
        stream: stream(1),
    })
    .unwrap();
    assert!(matches!(
        &link.receive(&guest.frame(&data(Channel::File, 1, &[1; 90])))[..],
        [LinkEvent::Request(GuestRequest::Data { .. })]
    ));
    let summary = link.channel(Channel::File);
    assert_eq!(summary.buffered_bytes, 90);
    assert_eq!(summary.receive_window_bytes, 60);
    assert_eq!(
        link.consume(Channel::File, 91),
        Err(ConsumeRefusal::MoreThanBuffered {
            channel: Channel::File,
            buffered_bytes: 90,
            consumed_bytes: 91
        })
    );
    assert_eq!(
        link.consume(Channel::Control, 1),
        Err(ConsumeRefusal::NotBulk {
            channel: Channel::Control
        })
    );
    link.consume(Channel::File, 40).unwrap();
    assert_eq!(link.channel(Channel::File).receive_window_bytes, 100);
    assert_eq!(link.channel(Channel::File).buffered_bytes, 50);
    let frames = drain(&mut link);
    assert!(frames.iter().any(|(_, message)| matches!(
        message,
        LinkMessage::WindowUpdate {
            channel: Channel::File,
            credit_bytes: 40
        }
    )));
    assert!(matches!(
        &link.receive(&guest.frame(&data(Channel::File, 1, &[2; 97])))[..],
        [LinkEvent::Request(GuestRequest::Data { .. })]
    ));
    assert_eq!(link.channel(Channel::File).receive_window_bytes, 3);
    assert_eq!(link.channel(Channel::File).buffered_bytes, 147);
    let events = link.receive(&guest.frame(&data(Channel::File, 1, &[3; 10])));
    assert_eq!(
        events,
        vec![
            LinkEvent::Refused(Refusal {
                reason: RefusalReason::WindowExceeded {
                    channel: Channel::File,
                    remaining_bytes: 3,
                    needed_bytes: 10
                },
                effect: RefusalEffect::ChannelClosed {
                    channel: Channel::File
                }
            }),
            LinkEvent::ChannelClosed {
                channel: Channel::File,
                cause: ChannelCloseCause::WindowExceeded {
                    remaining_bytes: 3,
                    needed_bytes: 10
                }
            },
        ]
    );
    assert_eq!(link.phase(), &LinkPhase::Open);
    assert_eq!(link.channel(Channel::File).streams, 0);
    let events = link.receive(&guest.frame(&file_open(3)));
    assert_eq!(
        refusal(&events).reason,
        RefusalReason::ChannelClosed {
            channel: Channel::File
        }
    );
    assert_eq!(
        link.consume(Channel::File, 1),
        Err(ConsumeRefusal::ChannelClosed {
            channel: Channel::File
        })
    );
    assert!(matches!(
        &link.receive(&guest.frame(&ping(9)))[..],
        [LinkEvent::Request(GuestRequest::Ping { nonce: 9 })]
    ));
    assert!(matches!(
        &link.receive(&guest.frame(&egress_open(1)))[..],
        [LinkEvent::Request(_)]
    ));
}

#[test]
fn the_host_respects_the_guests_credit() {
    let (mut link, _clock, mut guest) = link_with_file_stream();
    assert_eq!(
        link.send(HostMessage::Data {
            channel: Channel::File,
            stream: stream(1),
            bytes: vec![0; 10]
        }),
        Err(SendRefusal::NoCredit {
            channel: Channel::File,
            available_bytes: 0,
            needed_bytes: 10
        })
    );
    link.receive(&guest.frame(&LinkMessage::WindowUpdate {
        channel: Channel::File,
        credit_bytes: 15,
    }));
    assert_eq!(link.channel(Channel::File).send_credit_bytes, 15);
    link.send(HostMessage::Data {
        channel: Channel::File,
        stream: stream(1),
        bytes: vec![0; 10],
    })
    .unwrap();
    assert_eq!(
        link.send(HostMessage::Data {
            channel: Channel::File,
            stream: stream(1),
            bytes: vec![0; 6]
        }),
        Err(SendRefusal::NoCredit {
            channel: Channel::File,
            available_bytes: 5,
            needed_bytes: 6
        })
    );
    assert_eq!(link.channel(Channel::Terminal).send_credit_bytes, 0);
}

#[test]
fn half_close_ends_one_direction_at_a_time() {
    let (mut link, _clock, mut guest) = link_with_egress_stream();
    assert!(matches!(
        &link.receive(&guest.frame(&LinkMessage::EndOfStream {
            channel: Channel::Egress,
            stream: stream(1)
        }))[..],
        [LinkEvent::Request(GuestRequest::EndOfStream { .. })]
    ));
    let events = link.receive(&guest.frame(&data(Channel::Egress, 1, b"after")));
    assert_eq!(
        refusal(&events).reason,
        RefusalReason::HalfClosed {
            channel: Channel::Egress,
            stream: stream(1)
        }
    );
    let events = link.receive(&guest.frame(&LinkMessage::EndOfStream {
        channel: Channel::Egress,
        stream: stream(1),
    }));
    assert!(matches!(
        refusal(&events).reason,
        RefusalReason::HalfClosed { .. }
    ));
    link.send(HostMessage::Data {
        channel: Channel::Egress,
        stream: stream(1),
        bytes: b"still flows".to_vec(),
    })
    .unwrap();
    assert_eq!(link.channel(Channel::Egress).streams, 1);
    link.send(HostMessage::EndOfStream {
        channel: Channel::Egress,
        stream: stream(1),
    })
    .unwrap();
    assert_eq!(link.channel(Channel::Egress).streams, 0);
    assert_eq!(
        link.send(HostMessage::Data {
            channel: Channel::Egress,
            stream: stream(1),
            bytes: b"x".to_vec()
        }),
        Err(SendRefusal::StreamNotOpen {
            channel: Channel::Egress,
            stream: stream(1)
        })
    );

    let (mut link, _clock, mut guest) = link_with_egress_stream();
    link.send(HostMessage::EndOfStream {
        channel: Channel::Egress,
        stream: stream(1),
    })
    .unwrap();
    assert_eq!(
        link.send(HostMessage::Data {
            channel: Channel::Egress,
            stream: stream(1),
            bytes: b"x".to_vec()
        }),
        Err(SendRefusal::HalfClosed {
            channel: Channel::Egress,
            stream: stream(1)
        })
    );
    assert!(matches!(
        &link.receive(&guest.frame(&data(Channel::Egress, 1, b"guest still sends")))[..],
        [LinkEvent::Request(GuestRequest::Data { .. })]
    ));
}

// ---------------------------------------------------------------------------------------
// §3.2: independent quotas and priority of revocation over bulk
// ---------------------------------------------------------------------------------------

fn fill_bulk_queues(link: &mut TestLink, guest: &mut Guest) {
    // The ingress and egress streams open with windows of their own.
    for channel in Channel::BULK
        .into_iter()
        .filter(|channel| !channel.has_stream_windows())
    {
        let credit = LinkMessage::WindowUpdate {
            channel,
            credit_bytes: u32::MAX,
        };
        link.receive(&guest.frame(&credit));
    }
    link.receive(&guest.frame(&egress_open(1)));
    link.send(HostMessage::Opened {
        channel: Channel::Egress,
        stream: stream(1),
    })
    .unwrap();
    link.receive(&guest.frame(&LinkMessage::Open {
        stream: stream(1),
        open: StreamOpen::File {
            grant: GrantHandle(1),
            entry: name("f"),
            mode: FileMode::Read,
        },
    }));
    link.send(HostMessage::Opened {
        channel: Channel::File,
        stream: stream(1),
    })
    .unwrap();
    for (channel, open) in [
        (
            Channel::Terminal,
            HostMessage::OpenTerminal {
                stream: stream(2),
                columns: 1,
                rows: 1,
            },
        ),
        (
            Channel::Ingress,
            HostMessage::OpenIngress {
                stream: stream(2),
                listener: name("web"),
            },
        ),
    ] {
        link.send(open).unwrap();
        link.receive(&guest.frame(&LinkMessage::Opened {
            channel,
            stream: stream(2),
        }));
    }
    while link.next_outbound().is_some() {}
    for channel in Channel::BULK {
        let id = if channel == Channel::Terminal || channel == Channel::Ingress {
            2
        } else {
            1
        };
        let max = link.limits().quota(channel).max_queued_frames;
        for _ in 0..max {
            link.send(HostMessage::Data {
                channel,
                stream: stream(id),
                bytes: b"bulk".to_vec(),
            })
            .unwrap();
        }
        assert_eq!(
            link.send(HostMessage::Data {
                channel,
                stream: stream(id),
                bytes: b"bulk".to_vec()
            }),
            Err(SendRefusal::QueueFull {
                channel,
                max_queued_frames: max
            })
        );
    }
}

#[test]
fn a_bulk_flood_never_delays_a_revocation_or_lifecycle_control_frame() {
    let mut limits = LinkLimits::default();
    for channel in Channel::BULK {
        match channel {
            Channel::Terminal => limits.terminal.max_queued_frames = 50,
            Channel::File => limits.file.max_queued_frames = 50,
            Channel::Ingress => limits.ingress.max_queued_frames = 50,
            Channel::Egress => limits.egress.max_queued_frames = 50,
            Channel::Control => {}
        }
    }
    let (mut link, _clock, mut guest) = open_link(limits);
    fill_bulk_queues(&mut link, &mut guest);
    assert_eq!(link.queued_frames(), 200);
    link.send(HostMessage::Ping { nonce: 1 }).unwrap();
    link.send(HostMessage::Revoke(Revoke {
        reason: RevocationReason::SecurityEvent,
        authorization_epoch: AuthorizationEpoch::new(3),
    }))
    .unwrap();
    link.send(HostMessage::Shutdown(Shutdown { grace_seconds: 1 }))
        .unwrap();
    let frames = drain(&mut link);
    assert_eq!(frames.len(), 203);
    assert!(matches!(
        frames[0].1,
        LinkMessage::Revoke(Revoke {
            reason: RevocationReason::SecurityEvent,
            ..
        })
    ));
    assert!(matches!(frames[1].1, LinkMessage::Shutdown(_)));
    assert!(matches!(frames[2].1, LinkMessage::Ping { nonce: 1 }));
    let sequences: Vec<u64> = frames.iter().map(|(header, _)| header.sequence).collect();
    let first = sequences[0];
    assert!(sequences
        .iter()
        .enumerate()
        .all(|(index, sequence)| *sequence == first + index as u64));
    let bulk_channels: Vec<Channel> = frames[3..11]
        .iter()
        .map(|(header, _)| header.channel)
        .collect();
    assert_eq!(
        bulk_channels,
        vec![
            Channel::Terminal,
            Channel::File,
            Channel::Ingress,
            Channel::Egress,
            Channel::Terminal,
            Channel::File,
            Channel::Ingress,
            Channel::Egress
        ],
        "bulk channels take turns"
    );
}

#[test]
fn quotas_are_independent_per_channel() {
    let mut limits = LinkLimits::default();
    limits.terminal.max_queued_frames = 2;
    let (mut link, _clock, mut guest) = open_link(limits);
    link.receive(&guest.frame(&LinkMessage::WindowUpdate {
        channel: Channel::Terminal,
        credit_bytes: 1_000,
    }));
    link.receive(&guest.frame(&LinkMessage::WindowUpdate {
        channel: Channel::File,
        credit_bytes: 1_000,
    }));
    link.send(HostMessage::OpenTerminal {
        stream: stream(2),
        columns: 1,
        rows: 1,
    })
    .unwrap();
    link.receive(&guest.frame(&LinkMessage::Opened {
        channel: Channel::Terminal,
        stream: stream(2),
    }));
    link.send(HostMessage::OpenFile {
        stream: stream(2),
        grant: GrantHandle(4),
        entry: name("out.bin"),
        mode: FileMode::Write,
    })
    .unwrap();
    link.receive(&guest.frame(&LinkMessage::Opened {
        channel: Channel::File,
        stream: stream(2),
    }));
    while link.next_outbound().is_some() {}
    for _ in 0..2 {
        link.send(HostMessage::Data {
            channel: Channel::Terminal,
            stream: stream(2),
            bytes: b"t".to_vec(),
        })
        .unwrap();
    }
    assert_eq!(
        link.send(HostMessage::Data {
            channel: Channel::Terminal,
            stream: stream(2),
            bytes: b"t".to_vec()
        }),
        Err(SendRefusal::QueueFull {
            channel: Channel::Terminal,
            max_queued_frames: 2
        })
    );
    for _ in 0..10 {
        link.send(HostMessage::Data {
            channel: Channel::File,
            stream: stream(2),
            bytes: b"f".to_vec(),
        })
        .unwrap();
    }
    link.send(HostMessage::Ping { nonce: 1 }).unwrap();
    assert_eq!(link.channel(Channel::Terminal).queued_frames, 2);
    assert_eq!(link.channel(Channel::File).queued_frames, 10);
    assert_eq!(link.channel(Channel::Control).queued_frames, 1);
    let mut guest_limits = LinkLimits::default();
    guest_limits.file.max_streams = 1;
    let (mut link, _clock, mut guest) = open_link(guest_limits);
    link.receive(&guest.frame(&LinkMessage::Open {
        stream: stream(1),
        open: StreamOpen::File {
            grant: GrantHandle(1),
            entry: name("a"),
            mode: FileMode::Read,
        },
    }));
    assert!(matches!(
        refusal(&link.receive(&guest.frame(&LinkMessage::Open {
            stream: stream(3),
            open: StreamOpen::File {
                grant: GrantHandle(1),
                entry: name("b"),
                mode: FileMode::Read
            }
        })))
        .reason,
        RefusalReason::StreamQuotaExceeded {
            channel: Channel::File,
            ..
        }
    ));
    for id in [1, 3, 5] {
        assert!(matches!(
            &link.receive(&guest.frame(&egress_open(id)))[..],
            [LinkEvent::Request(_)]
        ));
    }
}

// ---------------------------------------------------------------------------------------
// Close, outbound sealing and host-side direction checks
// ---------------------------------------------------------------------------------------

#[test]
fn a_guest_close_or_host_close_ends_the_link_with_one_final_close_frame() {
    let (mut link, _clock, mut guest) = open_link(LinkLimits::default());
    link.send(HostMessage::Ping { nonce: 4 }).unwrap();
    let events = link.receive(&guest.frame(&LinkMessage::Close {
        reason: CloseReason::Orderly,
    }));
    assert_eq!(
        events,
        vec![
            LinkEvent::Request(GuestRequest::Close {
                reason: CloseReason::Orderly
            }),
            LinkEvent::Closed(CloseCause::GuestClosed {
                reason: CloseReason::Orderly
            }),
        ]
    );
    let frames = drain(&mut link);
    assert_eq!(
        frames.len(),
        1,
        "queued frames are dropped; only the close goes out"
    );
    assert!(matches!(
        frames[0].1,
        LinkMessage::Close {
            reason: CloseReason::Orderly
        }
    ));
    assert_eq!(
        link.send(HostMessage::Ping { nonce: 1 }),
        Err(SendRefusal::LinkClosed)
    );
    assert_eq!(
        link.consume(Channel::File, 0),
        Err(ConsumeRefusal::LinkClosed)
    );
    assert_eq!(link.tick(), vec![]);

    let (mut link, _clock, _guest) = open_link(LinkLimits::default());
    link.send(HostMessage::Close {
        reason: CloseReason::Shutdown,
    })
    .unwrap();
    assert_eq!(
        link.phase(),
        &LinkPhase::Closed(CloseCause::HostClosed {
            reason: CloseReason::Shutdown
        })
    );
    let frames = drain(&mut link);
    assert!(matches!(
        &frames[..],
        [(
            _,
            LinkMessage::Close {
                reason: CloseReason::Shutdown
            }
        )]
    ));
    assert_eq!(link.next_outbound(), None);
}

#[test]
fn outbound_frames_are_sealed_with_the_host_key_and_consecutive_sequences() {
    let (mut link, _clock, _guest) = link_with_egress_stream();
    link.send(HostMessage::Pong { nonce: 2 }).unwrap();
    link.send(HostMessage::Data {
        channel: Channel::Egress,
        stream: stream(1),
        bytes: b"payload".to_vec(),
    })
    .unwrap();
    let mut raw = Vec::new();
    while let Some(frame) = link.next_outbound() {
        raw.push(frame);
    }
    assert_eq!(raw.len(), 4, "welcome, opened, pong, data");
    let binding = binding();
    for (index, frame) in raw.iter().enumerate() {
        let (header, _) = decode_host_frame(&binding, frame);
        assert_eq!(header.sequence, index as u64 + 1);
        let parts = split_frame(frame).unwrap();
        assert!(!binding.verify(Sender::Guest, &head(frame), &parts.payload, &parts.tag));
        assert_eq!(frame.len(), FRAME_OVERHEAD_BYTES + parts.payload.len());
        assert_eq!(parts.tag.len(), TAG_BYTES);
    }
}

#[test]
fn the_host_cannot_send_guest_only_or_misrouted_operations() {
    let (mut link, _clock, _guest) = open_link(LinkLimits::default());
    assert_eq!(
        link.send(HostMessage::Opened {
            channel: Channel::Terminal,
            stream: stream(1)
        }),
        Err(SendRefusal::WrongChannel {
            channel: Channel::Terminal,
            operation: Operation::Opened
        })
    );
    assert_eq!(
        link.send(HostMessage::Data {
            channel: Channel::Control,
            stream: stream(2),
            bytes: vec![]
        }),
        Err(SendRefusal::WrongChannel {
            channel: Channel::Control,
            operation: Operation::Data
        })
    );
    assert_eq!(
        link.send(HostMessage::Resize {
            stream: stream(2),
            columns: 1,
            rows: 1
        }),
        Err(SendRefusal::StreamNotOpen {
            channel: Channel::Terminal,
            stream: stream(2)
        })
    );
    let too_long = vec![0u8; 16_382];
    assert!(matches!(
        link.send(HostMessage::Data {
            channel: Channel::Terminal,
            stream: stream(2),
            bytes: too_long
        }),
        Err(SendRefusal::MessageTooLarge {
            channel: Channel::Terminal,
            max_message_bytes: 16_384,
            ..
        })
    ));
}

#[test]
fn revocation_carries_the_core_06_reason_and_the_new_epoch() {
    let (mut link, _clock, _guest) = open_link(LinkLimits::default());
    link.send(HostMessage::Revoke(Revoke {
        reason: RevocationReason::OwnerReclaimed,
        authorization_epoch: AuthorizationEpoch::new(11),
    }))
    .unwrap();
    let frames = drain(&mut link);
    assert!(frames.iter().any(|(_, message)| {
        *message
            == LinkMessage::Revoke(Revoke {
                reason: RevocationReason::OwnerReclaimed,
                authorization_epoch: AuthorizationEpoch::new(11),
            })
    }));
}

// ---------------------------------------------------------------------------------------
// The conformance corpus (VM-CP-25, VM-W50)
// ---------------------------------------------------------------------------------------

struct CaseBuilder {
    name: &'static str,
    kind: CaseKind,
    notes: &'static str,
    steps: Vec<Step>,
    guest: Guest,
}

fn case(name: &'static str, kind: CaseKind, notes: &'static str) -> CaseBuilder {
    CaseBuilder {
        name,
        kind,
        notes,
        steps: Vec::new(),
        guest: Guest::on(corpus_nonce().connection()),
    }
}

impl CaseBuilder {
    fn guest(mut self, message: LinkMessage) -> Self {
        let frame = self.guest.frame(&message);
        self.steps.push(Step::Guest {
            frame_hex: hex::encode(frame),
        });
        self
    }

    fn raw(mut self, channel: Channel, code: u8, stream: u32, payload: &[u8]) -> Self {
        let frame = self.guest.raw(channel, code, stream, payload);
        self.steps.push(Step::Guest {
            frame_hex: hex::encode(frame),
        });
        self
    }

    fn bytes(mut self, frame: Vec<u8>) -> Self {
        self.guest.sequence += 1;
        self.steps.push(Step::Guest {
            frame_hex: hex::encode(frame),
        });
        self
    }

    fn host(mut self, action: HostAction) -> Self {
        self.steps.push(Step::Host { action });
        self
    }

    fn hello(self) -> Self {
        self.guest(hello())
    }

    fn accepted(self, link: LinkExpectation) -> CorpusCase {
        self.finish(Expectation {
            outcome: Outcome::Accepted,
            reason: None,
            link,
        })
    }

    fn refused(self, reason: &str, link: LinkExpectation) -> CorpusCase {
        self.finish(Expectation {
            outcome: Outcome::Refused,
            reason: Some(reason.to_owned()),
            link,
        })
    }

    fn finish(self, expect: Expectation) -> CorpusCase {
        CorpusCase {
            name: self.name.to_owned(),
            kind: self.kind,
            notes: self.notes.to_owned(),
            steps: self.steps,
            expect,
        }
    }
}

/// A hello on the corpus connection with the given sequence and generation, edited
/// after sealing.
fn sealed_hello_with(
    sequence: u64,
    boot_generation: u64,
    edit: impl FnOnce(&mut Vec<u8>),
) -> Vec<u8> {
    sealed_hello_on(corpus_nonce().connection(), sequence, boot_generation, edit)
}

fn sealed_hello_on(
    connection: Connection,
    sequence: u64,
    boot_generation: u64,
    edit: impl FnOnce(&mut Vec<u8>),
) -> Vec<u8> {
    let payload = hello().encode_payload().unwrap();
    let header = FrameHeader {
        channel: Channel::Control,
        operation_code: Operation::Hello.code(),
        stream: 0,
        sequence,
        boot_generation,
        payload_bytes: payload.len() as u32,
        connection,
    };
    let mut frame = seal(&binding(), Sender::Guest, &header, &payload);
    edit(&mut frame);
    frame
}

/// A hello framed as protocol version 1 did: the same first 32 header bytes with version
/// 1, no connection field, and the tag over that header and the payload.
pub(super) fn version_1_hello(binding: &LinkBinding, sequence: u64) -> Vec<u8> {
    let payload = hello().encode_payload().unwrap();
    let mut header = [0u8; 32];
    header[0..4].copy_from_slice(b"YGLK");
    header[4] = RETIRED_PROTOCOL_VERSION;
    header[5] = Channel::Control.code();
    header[6] = Operation::Hello.code();
    header[12..20].copy_from_slice(&sequence.to_be_bytes());
    header[20..28].copy_from_slice(&binding.boot().get().to_be_bytes());
    header[28..32].copy_from_slice(&(payload.len() as u32).to_be_bytes());
    let tag = binding.tag(Sender::Guest, &header, &payload);
    [&header[..], &payload, &tag].concat()
}

/// The connection of another connection of the corpus's boot.
fn earlier_connection() -> Connection {
    ConnectionNonce::new(b"corpus-conn-0000")
        .unwrap()
        .connection()
}

fn build_corpus() -> Corpus {
    use CaseKind::{Hostile, Valid};
    use LinkExpectation::{Closed, Open};
    let egress = Channel::Egress;
    let terminal = Channel::Terminal;
    let opened = |channel: Channel, stream: u32| HostAction::Opened { channel, stream };
    let init = |claimed_vm: Option<Digest>| {
        LinkMessage::InitReport(InitReport {
            stage: InitStage::Channel,
            outcome: ProbeOutcome::Passed,
            detail: "channel established".to_owned(),
            claimed_vm,
        })
    };
    let probe = LinkMessage::ProbeResult(ProbeResult {
        probe: name("seccomp-profile"),
        outcome: ProbeOutcome::Passed,
        detail: String::new(),
    });
    let file_open = |id: u32| LinkMessage::Open {
        stream: stream(id),
        open: StreamOpen::File {
            grant: GrantHandle(7),
            entry: name("notes.txt"),
            mode: FileMode::Read,
        },
    };
    let eos = |channel: Channel, id: u32| LinkMessage::EndOfStream {
        channel,
        stream: stream(id),
    };
    let cancel = |channel: Channel, id: u32| LinkMessage::Cancel {
        channel,
        stream: stream(id),
        cause: CancelCause::Requested,
    };
    let guest_opened = |channel: Channel, id: u32| LinkMessage::Opened {
        channel,
        stream: stream(id),
    };
    let ping_code = Operation::Ping.code();
    let control = Channel::Control;

    let cases = vec![
        case("hello", Valid, "the first guest frame, after the host's challenge: version 3, agent build, no claims").hello().accepted(Open),
        case("hello-with-claims", Valid, "claimed VM and boot that agree with the binding are accepted but never used as identity")
            .guest(LinkMessage::Hello(Hello {
                guest_version: PROTOCOL_VERSION,
                agent_build: digest("yougori/link/corpus/v1", &[b"agent-build"]),
                claimed_vm: Some(vm().digest()),
                claimed_boot: Some(BOOT),
            }))
            .accepted(Open),
        case("ping", Valid, "liveness").hello().guest(ping(42)).accepted(Open),
        case("pong", Valid, "answer to a host ping").hello().guest(LinkMessage::Pong { nonce: 7 }).accepted(Open),
        case("init-report", Valid, "a guest report with a claimed VM that agrees").hello().guest(init(Some(vm().digest()))).accepted(Open),
        case("probe-result", Valid, "a guest report").hello().guest(probe.clone()).accepted(Open),
        case("all-probes-passed", Valid, "a guest report; it satisfies no host-only requirement")
            .hello()
            .guest(LinkMessage::AllProbesPassed(AllProbesPassed { probe_count: 12 }))
            .accepted(Open),
        case("window-update", Valid, "credit for host-to-guest terminal data, which is flow-controlled per channel")
            .hello()
            .guest(LinkMessage::WindowUpdate { channel: terminal, credit_bytes: 4_096 })
            .accepted(Open),
        case("stream-window-update", Valid, "credit for host-to-guest data on one egress stream: version 3 flow-controls the ingress and egress channels per stream")
            .hello()
            .guest(egress_open(1))
            .host(opened(egress, 1))
            .guest(LinkMessage::StreamWindowUpdate { channel: egress, stream: stream(1), credit_bytes: 4_096 })
            .accepted(Open),
        case("stream-window-update-after-both-ends", Valid, "credit that crossed the stream's finish is dropped without a refusal")
            .hello()
            .guest(egress_open(1))
            .host(opened(egress, 1))
            .host(HostAction::EndOfStream { channel: egress, stream: 1 })
            .guest(eos(egress, 1))
            .guest(LinkMessage::StreamWindowUpdate { channel: egress, stream: stream(1), credit_bytes: 4_096 })
            .accepted(Open),
        case("egress-open", Valid, "a destination name, never an address").hello().guest(egress_open(1)).accepted(Open),
        case("egress-two-streams", Valid, "guest stream ids rise").hello().guest(egress_open(1)).guest(egress_open(3)).accepted(Open),
        case("egress-data", Valid, "data after the host accepted the open")
            .hello().guest(egress_open(1)).host(opened(egress, 1)).guest(data(egress, 1, b"GET / HTTP/1.1\r\n")).accepted(Open),
        case("egress-end-of-stream", Valid, "half-close by the guest")
            .hello().guest(egress_open(1)).host(opened(egress, 1)).guest(eos(egress, 1)).accepted(Open),
        case("egress-both-ends", Valid, "the host ended first, then the guest")
            .hello().guest(egress_open(1)).host(opened(egress, 1)).host(HostAction::EndOfStream { channel: egress, stream: 1 }).guest(eos(egress, 1)).accepted(Open),
        case("egress-cancel", Valid, "cancel by the guest")
            .hello().guest(egress_open(1)).host(opened(egress, 1)).guest(cancel(egress, 1)).accepted(Open),
        case("file-open", Valid, "a grant handle and one entry name, never a path").hello().guest(file_open(1)).accepted(Open),
        case("file-host-opened-data", Valid, "a host-opened file stream the guest accepted")
            .hello()
            .host(HostAction::OpenFile { stream: 2, grant: 9, entry: name("out.bin"), mode: FileMode::Write })
            .guest(guest_opened(Channel::File, 2))
            .guest(data(Channel::File, 2, &[0, 1, 2, 3]))
            .accepted(Open),
        case("terminal-opened-data", Valid, "a host-opened terminal")
            .hello()
            .host(HostAction::OpenTerminal { stream: 2, columns: 80, rows: 24 })
            .guest(guest_opened(terminal, 2))
            .guest(data(terminal, 2, b"$ "))
            .accepted(Open),
        case("terminal-exit", Valid, "the exit is a guest report")
            .hello()
            .host(HostAction::OpenTerminal { stream: 2, columns: 80, rows: 24 })
            .guest(guest_opened(terminal, 2))
            .guest(LinkMessage::Exit { stream: stream(2), code: 0 })
            .accepted(Open),
        case("terminal-open-refused", Valid, "the guest refuses a host open")
            .hello()
            .host(HostAction::OpenTerminal { stream: 2, columns: 80, rows: 24 })
            .guest(LinkMessage::OpenRefused { channel: terminal, stream: stream(2), cause: OpenRefusalCause::Unavailable })
            .accepted(Open),
        case("ingress-opened-data", Valid, "a host-opened ingress stream")
            .hello()
            .host(HostAction::OpenIngress { stream: 2, listener: name("web") })
            .guest(guest_opened(Channel::Ingress, 2))
            .guest(data(Channel::Ingress, 2, b"HTTP/1.1 200 OK\r\n"))
            .accepted(Open),
        case("close", Valid, "orderly close by the guest").hello().guest(LinkMessage::Close { reason: CloseReason::Orderly }).accepted(Closed),
        // Hostile: framing (unauthenticated bytes close the link).
        case("bad-magic", Hostile, "").bytes(sealed_hello_with(1, BOOT, |f| f[0] = b'X')).refused("framing.bad_magic", Closed),
        case("unsupported-version", Hostile, "").bytes(sealed_hello_with(1, BOOT, |f| f[4] = 4)).refused("framing.unsupported_version", Closed),
        case("version-2", Hostile, "a hello framed as protocol version 2, whose ingress and egress windows were per channel").bytes(sealed_hello_with(1, BOOT, |f| f[4] = 2)).refused("framing.unsupported_version", Closed),
        case("retired-version", Hostile, "a hello framed as protocol version 1, bound to the boot only").bytes(version_1_hello(&binding(), 1)).refused("framing.retired_version", Closed),
        case("unknown-channel", Hostile, "").bytes(sealed_hello_with(1, BOOT, |f| f[5] = 9)).refused("framing.unknown_channel", Closed),
        case("reserved-flags", Hostile, "").bytes(sealed_hello_with(1, BOOT, |f| f[7] = 0x80)).refused("framing.reserved_flags", Closed),
        case("oversized", Hostile, "the header announces more than the frame limit")
            .bytes(sealed_hello_with(1, BOOT, |f| f[28..32].copy_from_slice(&65_473u32.to_be_bytes())))
            .refused("framing.oversized", Closed),
        case("bad-tag", Hostile, "one flipped tag bit").bytes(sealed_hello_with(1, BOOT, |f| { let i = f.len() - 1; f[i] ^= 1; })).refused("unauthenticated", Closed),
        case("stale-generation", Hostile, "bound to the previous boot; the key differs too").bytes(sealed_hello_with(1, BOOT - 1, |_| {})).refused("stale_generation", Closed),
        case("future-generation", Hostile, "").bytes(sealed_hello_with(1, BOOT + 1, |_| {})).refused("stale_generation", Closed),
        // Hostile: the connection binding (frames of another connection of the same boot).
        case("hello-from-earlier-connection", Hostile, "a hello recorded on an earlier connection of the boot").bytes(sealed_hello_on(earlier_connection(), 1, BOOT, |_| {})).refused("stale_connection", Closed),
        case("hello-unchallenged", Hostile, "a hello that ignores the challenge").bytes(sealed_hello_on(Connection::UNCHALLENGED, 1, BOOT, |_| {})).refused("stale_connection", Closed),
        case("hello-moved-to-this-connection", Hostile, "an earlier connection's hello with this connection written over its field; the tag covers the field")
            .bytes(sealed_hello_on(earlier_connection(), 1, BOOT, |f| f[32..48].copy_from_slice(corpus_nonce().connection().as_bytes())))
            .refused("unauthenticated", Closed),
        case("ping-from-earlier-connection", Hostile, "the next frame of an earlier connection, after this connection's hello")
            .hello()
            .bytes(encode_frame_on(&binding(), earlier_connection(), Sender::Guest, 2, &ping(1)).unwrap())
            .refused("stale_connection", Closed),
        case("window-update-from-earlier-connection", Hostile, "an acknowledgment of credit recorded on an earlier connection")
            .hello()
            .bytes(encode_frame_on(&binding(), earlier_connection(), Sender::Guest, 2, &LinkMessage::WindowUpdate { channel: terminal, credit_bytes: 4_096 }).unwrap())
            .refused("stale_connection", Closed),
        case("guest-challenge", Hostile, "host-only operation").hello().guest(LinkMessage::Challenge { connection: earlier_connection() }).refused("wrong_direction", Open),
        case("replayed-sequence", Hostile, "the hello again with sequence 1").hello().bytes(sealed_hello_with(1, BOOT, |_| {})).refused("sequence.replayed", Closed),
        case("sequence-zero", Hostile, "").hello().bytes(encode_frame_on(&binding(), corpus_nonce().connection(), Sender::Guest, 0, &ping(1)).unwrap()).refused("sequence.replayed", Closed),
        case("reordered-sequence", Hostile, "sequence 3 where 2 was expected").hello().bytes(encode_frame_on(&binding(), corpus_nonce().connection(), Sender::Guest, 3, &ping(1)).unwrap()).refused("sequence.reordered", Closed),
        // Hostile: the guest tries to select a host action.
        case("guest-revoke", Hostile, "host-only operation").hello().guest(LinkMessage::Revoke(Revoke { reason: RevocationReason::UserRequested, authorization_epoch: AuthorizationEpoch::new(1) })).refused("wrong_direction", Open),
        case("guest-welcome", Hostile, "").hello().guest(LinkMessage::Welcome(super::messages::WelcomeTerms { version: 1, max_frame_bytes: 1, idle_timeout_seconds: 1 })).refused("wrong_direction", Open),
        case("guest-shutdown", Hostile, "").hello().guest(LinkMessage::Shutdown(Shutdown { grace_seconds: 0 })).refused("wrong_direction", Open),
        case("guest-open-terminal", Hostile, "").hello().guest(LinkMessage::Open { stream: stream(1), open: StreamOpen::Terminal { columns: 1, rows: 1 } }).refused("wrong_direction", Open),
        case("guest-open-ingress", Hostile, "").hello().guest(LinkMessage::Open { stream: stream(1), open: StreamOpen::Ingress { listener: name("x") } }).refused("wrong_direction", Open),
        case("guest-resize", Hostile, "").hello().guest(LinkMessage::Resize { stream: stream(1), columns: 1, rows: 1 }).refused("wrong_direction", Open),
        case("unknown-operation", Hostile, "code 0x7f").hello().raw(control, 0x7f, 0, &[]).refused("unknown_operation", Open),
        case("data-on-control", Hostile, "a stream operation on the control channel").hello().raw(control, Operation::Data.code(), 1, &[]).refused("unknown_operation", Open),
        case("window-update-on-egress", Hostile, "the egress channel is credited per stream; channel credit does not exist there")
            .hello()
            .raw(egress, Operation::WindowUpdate.code(), 0, &FieldWriter::new().u32(1, 4_096).finish())
            .refused("unknown_operation", Open),
        case("stream-window-update-on-terminal", Hostile, "the terminal channel is credited as a whole")
            .hello()
            .host(HostAction::OpenTerminal { stream: 2, columns: 80, rows: 24 })
            .guest(guest_opened(terminal, 2))
            .raw(terminal, Operation::StreamWindowUpdate.code(), 2, &FieldWriter::new().u32(1, 4_096).finish())
            .refused("unknown_operation", Open),
        // Hostile: handshake and identity.
        case("hello-twice", Hostile, "").hello().hello().refused("handshake_repeated", Open),
        case("ping-before-hello", Hostile, "").guest(ping(1)).refused("handshake_incomplete", Open),
        case("hello-version-1", Hostile, "a version 2 frame whose hello claims version 1").guest(LinkMessage::Hello(Hello { guest_version: RETIRED_PROTOCOL_VERSION, agent_build: digest("yougori/link/corpus/v1", &[b"agent-build"]), claimed_vm: None, claimed_boot: None })).refused("unsupported_guest_version", Closed),
        case("hello-version-2", Hostile, "a version 3 frame whose hello claims version 2").guest(LinkMessage::Hello(Hello { guest_version: 2, agent_build: digest("yougori/link/corpus/v1", &[b"agent-build"]), claimed_vm: None, claimed_boot: None })).refused("unsupported_guest_version", Closed),
        case("hello-version-4", Hostile, "").guest(LinkMessage::Hello(Hello { guest_version: 4, agent_build: digest("yougori/link/corpus/v1", &[b"agent-build"]), claimed_vm: None, claimed_boot: None })).refused("unsupported_guest_version", Closed),
        case("hello-claims-other-vm", Hostile, "a guest-supplied VM id is never identity")
            .guest(LinkMessage::Hello(Hello { guest_version: PROTOCOL_VERSION, agent_build: digest("yougori/link/corpus/v1", &[b"agent-build"]), claimed_vm: Some(other_vm().digest()), claimed_boot: None }))
            .refused("claimed_identity_disagrees", Closed),
        case("hello-claims-other-boot", Hostile, "")
            .guest(LinkMessage::Hello(Hello { guest_version: PROTOCOL_VERSION, agent_build: digest("yougori/link/corpus/v1", &[b"agent-build"]), claimed_vm: None, claimed_boot: Some(BOOT - 1) }))
            .refused("claimed_identity_disagrees", Closed),
        case("init-report-claims-other-vm", Hostile, "").hello().guest(init(Some(other_vm().digest()))).refused("claimed_identity_disagrees", Closed),
        case("hello-unknown-field", Hostile, "").raw(control, Operation::Hello.code(), 0, &FieldWriter::new().u8(1, 1).digest(2, &vm().digest()).u8(5, 1).finish()).refused("payload.unknown_field", Open),
        // Hostile: payload fields.
        case("duplicate-field", Hostile, "").hello().raw(control, ping_code, 0, &FieldWriter::new().u64(1, 1).u64(1, 1).finish()).refused("payload.duplicate_field", Open),
        case("unknown-field", Hostile, "").hello().raw(control, ping_code, 0, &FieldWriter::new().u64(1, 1).u8(2, 1).finish()).refused("payload.unknown_field", Open),
        case("missing-field", Hostile, "").hello().raw(control, ping_code, 0, &[]).refused("payload.missing_field", Open),
        case("truncated-value", Hostile, "").hello().raw(control, ping_code, 0, &[1, 0, 8, 1, 2]).refused("payload.truncated_value", Open),
        case("truncated-header", Hostile, "").hello().raw(control, ping_code, 0, &[1, 0]).refused("payload.truncated_header", Open),
        case("wrong-length", Hostile, "a four-byte nonce").hello().raw(control, ping_code, 0, &FieldWriter::new().u32(1, 1).finish()).refused("payload.wrong_length", Open),
        case("file-entry-is-a-path", Hostile, "").hello().raw(Channel::File, Operation::Open.code(), 1, &FieldWriter::new().u64(1, 7).text(2, "../etc/passwd").unwrap().u8(3, 1).finish()).refused("payload.not_name", Open),
        case("egress-destination-is-a-url", Hostile, "").hello().raw(egress, Operation::Open.code(), 1, &FieldWriter::new().text(1, "http://evil.example/").unwrap().finish()).refused("payload.not_name", Open),
        case("detail-too-long", Hostile, "").hello().raw(control, Operation::InitReport.code(), 0, &FieldWriter::new().u8(1, 1).u8(2, 1).text(3, &"x".repeat(300)).unwrap().finish()).refused("payload.too_long", Open),
        case("invalid-outcome", Hostile, "").hello().raw(control, Operation::ProbeResult.code(), 0, &FieldWriter::new().text(1, "p").unwrap().u8(2, 9).text(3, "").unwrap().finish()).refused("payload.invalid_value", Open),
        case("detail-not-text", Hostile, "").hello().raw(control, Operation::ProbeResult.code(), 0, &FieldWriter::new().text(1, "p").unwrap().u8(2, 1).bytes(3, b"a\x00b").unwrap().finish()).refused("payload.not_text", Open),
        case("nested-payload", Hostile, "the nonce field holds a payload; the parser reads one level and refuses the length")
            .hello()
            .raw(control, ping_code, 0, &{
                let mut payload = ping(1).encode_payload().unwrap();
                for _ in 0..100 {
                    payload = FieldWriter::new().bytes(1, &payload).unwrap().finish();
                }
                payload
            })
            .refused("payload.wrong_length", Open),
        case("message-too-large", Hostile, "5 000 bytes on the control channel").hello().raw(control, ping_code, 0, &FieldWriter::new().u64(1, 1).bytes(2, &[0; 5_000]).unwrap().finish()).refused("message_too_large", Open),
        // Hostile: stream state.
        case("ping-with-stream", Hostile, "").hello().raw(control, ping_code, 1, &ping(1).encode_payload().unwrap()).refused("stream_id_forbidden", Open),
        case("open-stream-zero", Hostile, "").hello().raw(egress, Operation::Open.code(), 0, &egress_open(1).encode_payload().unwrap()).refused("stream_id_required", Open),
        case("even-guest-stream", Hostile, "").hello().guest(egress_open(2)).refused("stream_parity", Open),
        case("stream-id-not-increasing", Hostile, "").hello().guest(egress_open(3)).guest(egress_open(1)).refused("stream_id_not_increasing", Open),
        case("data-on-unopened-stream", Hostile, "").hello().guest(data(egress, 1, b"x")).refused("stream_not_open", Open),
        case("stream-window-update-on-unopened-stream", Hostile, "")
            .hello()
            .guest(LinkMessage::StreamWindowUpdate { channel: egress, stream: stream(1), credit_bytes: 4_096 })
            .refused("stream_not_open", Open),
        case("stream-window-update-without-stream", Hostile, "")
            .hello()
            .raw(egress, Operation::StreamWindowUpdate.code(), 0, &FieldWriter::new().u32(1, 4_096).finish())
            .refused("stream_id_required", Open),
        case("stream-window-update-after-cancel", Hostile, "credit in flight when the guest cancelled: refused without charge to the budget")
            .hello()
            .guest(egress_open(1))
            .host(opened(egress, 1))
            .guest(cancel(egress, 1))
            .guest(LinkMessage::StreamWindowUpdate { channel: egress, stream: stream(1), credit_bytes: 4_096 })
            .refused("stream_cancelled", Open),
        case("data-before-host-opened", Hostile, "").hello().guest(egress_open(1)).guest(data(egress, 1, b"x")).refused("stream_not_open", Open),
        case("data-after-end-of-stream", Hostile, "").hello().guest(egress_open(1)).host(opened(egress, 1)).guest(eos(egress, 1)).guest(data(egress, 1, b"x")).refused("half_closed", Open),
        case("end-of-stream-twice", Hostile, "").hello().guest(egress_open(1)).host(opened(egress, 1)).guest(eos(egress, 1)).guest(eos(egress, 1)).refused("half_closed", Open),
        case("data-after-cancel", Hostile, "refused without charge to the budget").hello().guest(egress_open(1)).host(opened(egress, 1)).guest(cancel(egress, 1)).guest(data(egress, 1, b"x")).refused("stream_cancelled", Open),
        case("data-after-host-cancel", Hostile, "output in flight when the host cancelled: refused without charge to the budget, counted against the window and credited straight back")
            .hello()
            .host(HostAction::OpenTerminal { stream: 2, columns: 80, rows: 24 })
            .guest(guest_opened(terminal, 2))
            .host(HostAction::Cancel { channel: terminal, stream: 2, cause: CancelCause::QuotaExceeded })
            .guest(data(terminal, 2, b"late output"))
            .refused("stream_cancelled", Open),
        case("opened-twice", Hostile, "").hello().host(HostAction::OpenTerminal { stream: 2, columns: 1, rows: 1 }).guest(guest_opened(terminal, 2)).guest(guest_opened(terminal, 2)).refused("stream_not_opening", Open),
        case("guest-answers-its-own-open", Hostile, "the file channel opens both ways; the opener never answers").hello().guest(file_open(1)).guest(guest_opened(Channel::File, 1)).refused("stream_not_opening", Open),
        case("guest-answers-egress-open", Hostile, "on egress only the host answers").hello().guest(egress_open(1)).guest(guest_opened(egress, 1)).refused("wrong_direction", Open),
        case("exit-on-unopened-terminal", Hostile, "").hello().guest(LinkMessage::Exit { stream: stream(2), code: 1 }).refused("stream_not_open", Open),
        case("frame-after-close", Hostile, "").hello().guest(LinkMessage::Close { reason: CloseReason::Orderly }).guest(ping(1)).refused("link_already_closed", Closed),
    ];
    Corpus {
        format: CORPUS_FORMAT.to_owned(),
        protocol_version: PROTOCOL_VERSION,
        secret_hex: hex::encode(secret_bytes()),
        vm_hex: vm().digest().to_hex(),
        boot_generation: BOOT,
        connection_hex: corpus_nonce().connection().to_hex(),
        challenge_hex: hex::encode(
            encode_frame_on(
                &binding(),
                corpus_nonce().connection(),
                Sender::Host,
                1,
                &LinkMessage::Challenge {
                    connection: corpus_nonce().connection(),
                },
            )
            .unwrap(),
        ),
        cases,
    }
}

#[test]
fn the_corpus_fixture_matches_the_encoder() {
    let generated = serde_json::to_string_pretty(&build_corpus()).unwrap() + "\n";
    if generated != super::corpus::CORPUS_JSON {
        println!("=====BEGIN GENERATED CORPUS=====");
        println!("{generated}");
        println!("=====END GENERATED CORPUS=====");
        panic!("corpus.json differs from the encoder's output; replace it with the generated text");
    }
}

#[test]
fn the_shipped_corpus_parses_and_is_strict() {
    let corpus = Corpus::shipped().unwrap();
    assert_eq!(corpus.format, CORPUS_FORMAT);
    assert_eq!(corpus.protocol_version, PROTOCOL_VERSION);
    let valid = corpus
        .cases
        .iter()
        .filter(|case| case.kind == CaseKind::Valid)
        .count();
    let hostile = corpus
        .cases
        .iter()
        .filter(|case| case.kind == CaseKind::Hostile)
        .count();
    assert!(valid >= 20, "{valid}");
    assert!(hostile >= 50, "{hostile}");
    let names: std::collections::BTreeSet<&str> =
        corpus.cases.iter().map(|case| case.name.as_str()).collect();
    assert_eq!(names.len(), corpus.cases.len(), "case names are unique");
    let mut json: serde_json::Value = serde_json::from_str(super::corpus::CORPUS_JSON).unwrap();
    json["extra"] = serde_json::json!(1);
    assert!(Corpus::parse(&json.to_string()).is_err());
    assert!(matches!(
        Corpus::parse(
            r#"{"format":"other","protocol_version":2,"secret_hex":"","vm_hex":"","boot_generation":1,"connection_hex":"","challenge_hex":"","cases":[]}"#
        ),
        Err(super::corpus::CorpusError::WrongFormat { .. })
    ));
}

#[test]
fn every_corpus_case_replays_as_it_expects() {
    let corpus = Corpus::shipped().unwrap();
    for case in &corpus.cases {
        let outcome = replay(&corpus, case, LinkLimits::default(), None, Feed::Whole)
            .unwrap_or_else(|error| panic!("{}: {error}", case.name));
        assert!(
            outcome.matches(&case.expect),
            "{}: {outcome:?} vs {:?}",
            case.name,
            case.expect
        );
        assert!(outcome.peak_decoder_bytes <= 65_536);
        if case.kind == CaseKind::Valid {
            assert_eq!(outcome.last, LastOutcome::Accepted, "{}", case.name);
        }
    }
}

#[test]
fn the_vm_cp_25_mutations_of_every_valid_frame_are_bounded_refusals() {
    let corpus = Corpus::shipped().unwrap();
    let limits = LinkLimits::default();
    let binding = corpus.binding().unwrap();
    let mut mutated = 0;
    for case in corpus
        .cases
        .iter()
        .filter(|case| case.kind == CaseKind::Valid)
    {
        let last_hex = case
            .steps
            .iter()
            .rev()
            .find_map(|step| match step {
                Step::Guest { frame_hex } => Some(frame_hex.clone()),
                Step::Host { .. } => None,
            })
            .unwrap();
        let frame = hex::decode(last_hex).unwrap();
        let operation = operation_of(&frame).unwrap();
        let baseline = replay(&corpus, case, limits, None, Feed::Whole).unwrap();
        for mutation in Mutation::ALL {
            let frames = mutate(&binding, &limits, &frame, mutation).unwrap();
            let feed = match mutation {
                Mutation::Slow => Feed::OneByteAtATime,
                Mutation::Truncated => Feed::WholeThenDisconnect,
                _ => Feed::Whole,
            };
            let outcome = replay(&corpus, case, limits, Some(&frames), feed)
                .unwrap_or_else(|error| panic!("{} {mutation:?}: {error}", case.name));
            assert!(
                outcome.peak_decoder_bytes <= limits.max_frame_bytes as usize,
                "{} {mutation:?}",
                case.name
            );
            assert!(
                outcome.peak_buffered_bytes <= 8 << 20,
                "{} {mutation:?}",
                case.name
            );
            let code = match &outcome.last {
                LastOutcome::Accepted => None,
                LastOutcome::Refused { code } => Some(code.as_str()),
            };
            match mutation {
                Mutation::Oversized => {
                    assert_eq!(code, Some("framing.oversized"), "{}", case.name);
                    assert!(!outcome.link_open);
                }
                Mutation::Truncated => {
                    assert_eq!(code, Some("framing.truncated"), "{}", case.name);
                    assert!(!outcome.link_open);
                }
                Mutation::Slow => {
                    assert_eq!(outcome.last, baseline.last, "{}", case.name);
                    assert_eq!(outcome.link_open, baseline.link_open);
                }
                Mutation::Recursive => match operation {
                    Operation::Data => assert!(
                        code.is_none() || code.is_some_and(|code| code.starts_with("payload.")),
                        "{}: {code:?}",
                        case.name
                    ),
                    _ => assert!(
                        code.is_some_and(|code| code.starts_with("payload.")),
                        "{}: {code:?}",
                        case.name
                    ),
                },
                Mutation::DuplicateField => assert!(
                    matches!(
                        code,
                        Some(
                            "payload.duplicate_field"
                                | "payload.unknown_field"
                                | "message_too_large"
                        )
                    ),
                    "{}: {code:?}",
                    case.name
                ),
                // A cancel of a stream not yet open, or a close before the hello, is
                // itself the refused frame; the frame after it is then accepted.
                Mutation::Cancelled => assert!(
                    matches!(
                        code,
                        Some(
                            "stream_cancelled"
                                | "stream_not_open"
                                | "link_already_closed"
                                | "handshake_incomplete"
                        )
                    ),
                    "{}: {code:?}",
                    case.name
                ),
            }
            mutated += 1;
        }
    }
    assert!(mutated >= 120, "{mutated}");
}

#[test]
fn an_inconsistent_corpus_case_is_reported() {
    let corpus = Corpus::shipped().unwrap();
    let bad_setup = case("bad-setup", CaseKind::Hostile, "")
        .guest(ping(1))
        .guest(ping(2))
        .refused("x", LinkExpectation::Open);
    assert!(matches!(
        replay(
            &corpus,
            &bad_setup,
            LinkLimits::default(),
            None,
            Feed::Whole
        ),
        Err(super::corpus::CorpusError::SetupRefused { step: 0, .. })
    ));
    let no_frames = case("no-frames", CaseKind::Valid, "")
        .host(HostAction::Close {
            reason: CloseReason::Orderly,
        })
        .accepted(LinkExpectation::Open);
    assert_eq!(
        replay(
            &corpus,
            &no_frames,
            LinkLimits::default(),
            None,
            Feed::Whole
        )
        .err(),
        Some(super::corpus::CorpusError::NoGuestFrames)
    );
}

// ---------------------------------------------------------------------------------------
// Credit across cancels (review of link v2): a cancel never shrinks a window
// ---------------------------------------------------------------------------------------

#[test]
fn a_cancel_returns_the_credit_of_data_still_queued() {
    let (mut link, _clock, mut guest) = link_with_file_stream();
    let events = link.receive(&guest.frame(&file_open(3)));
    assert!(matches!(&events[..], [LinkEvent::Request(_)]), "{events:?}");
    link.send(HostMessage::Opened {
        channel: Channel::File,
        stream: stream(3),
    })
    .unwrap();
    link.receive(&guest.frame(&LinkMessage::WindowUpdate {
        channel: Channel::File,
        credit_bytes: 1_000,
    }));
    drain(&mut link);
    let send = |link: &mut TestLink, id: u32, bytes: usize| {
        link.send(HostMessage::Data {
            channel: Channel::File,
            stream: stream(id),
            bytes: vec![7; bytes],
        })
        .unwrap();
    };
    // Written data stays charged: the guest received it and credits it as it consumes.
    send(&mut link, 1, 100);
    assert_eq!(drain(&mut link).len(), 1);
    send(&mut link, 1, 200);
    send(&mut link, 1, 300);
    send(&mut link, 3, 50);
    assert_eq!(link.channel(Channel::File).send_credit_bytes, 350);

    // The host cancels stream 1: its two queued frames are dropped and their 500 bytes
    // of credit come back; stream 3's queued data stays charged.
    link.send(HostMessage::Cancel {
        channel: Channel::File,
        stream: stream(1),
        cause: CancelCause::Requested,
    })
    .unwrap();
    assert_eq!(link.channel(Channel::File).send_credit_bytes, 850);
    // The guest cancels stream 3: its queued 50 bytes come back too.
    link.receive(&guest.frame(&LinkMessage::Cancel {
        channel: Channel::File,
        stream: stream(3),
        cause: CancelCause::Requested,
    }));
    assert_eq!(link.channel(Channel::File).send_credit_bytes, 900);
    let frames = drain(&mut link);
    assert!(frames
        .iter()
        .all(|(_, message)| !matches!(message, LinkMessage::Data { .. })));
}

#[test]
fn data_for_a_cancelled_stream_counts_against_the_window_and_is_credited_straight_back() {
    let (mut link, _clock, mut guest) = link_with_file_stream();
    drain(&mut link);
    let window = link.channel(Channel::File).receive_window_bytes;
    link.send(HostMessage::Cancel {
        channel: Channel::File,
        stream: stream(1),
        cause: CancelCause::QuotaExceeded,
    })
    .unwrap();
    drain(&mut link);
    let events = link.receive(&guest.frame(&data(Channel::File, 1, &[1; 500])));
    assert_refused(
        &events,
        RefusalReason::StreamCancelled {
            channel: Channel::File,
            stream: stream(1),
        },
        RefusalEffect::FrameDropped,
    );
    assert_eq!(link.refusals(), 0);
    let summary = link.channel(Channel::File);
    assert_eq!(summary.receive_window_bytes, window);
    assert_eq!(summary.buffered_bytes, 0);
    assert_eq!(
        drain(&mut link)
            .into_iter()
            .map(|(_, message)| message)
            .collect::<Vec<_>>(),
        vec![LinkMessage::WindowUpdate {
            channel: Channel::File,
            credit_bytes: 500
        }]
    );

    // Late data still may not pass the window: an overrun closes the channel.
    let mut limits = LinkLimits::default();
    limits.file.max_message_bytes = 1_024;
    limits.file.max_buffered_bytes = 1_024;
    let (mut link, _clock, mut guest) = open_link(limits);
    link.receive(&guest.frame(&file_open(1)));
    link.send(HostMessage::Opened {
        channel: Channel::File,
        stream: stream(1),
    })
    .unwrap();
    link.receive(&guest.frame(&data(Channel::File, 1, &[1; 1_000])));
    link.send(HostMessage::Cancel {
        channel: Channel::File,
        stream: stream(1),
        cause: CancelCause::Requested,
    })
    .unwrap();
    let events = link.receive(&guest.frame(&data(Channel::File, 1, &[1; 100])));
    assert_refused(
        &events,
        RefusalReason::WindowExceeded {
            channel: Channel::File,
            remaining_bytes: 24,
            needed_bytes: 100,
        },
        RefusalEffect::ChannelClosed {
            channel: Channel::File,
        },
    );
}

#[test]
fn credit_for_dropped_data_waits_for_room_in_a_full_queue() {
    let mut limits = LinkLimits::default();
    limits.file.max_queued_frames = 1;
    let (mut link, _clock, mut guest) = open_link(limits);
    link.receive(&guest.frame(&file_open(1)));
    link.receive(&guest.frame(&file_open(3)));
    link.send(HostMessage::Opened {
        channel: Channel::File,
        stream: stream(1),
    })
    .unwrap();
    drain(&mut link);
    link.send(HostMessage::Opened {
        channel: Channel::File,
        stream: stream(3),
    })
    .unwrap();
    let window = link.channel(Channel::File).receive_window_bytes;
    link.receive(&guest.frame(&LinkMessage::Cancel {
        channel: Channel::File,
        stream: stream(1),
        cause: CancelCause::Requested,
    }));
    link.receive(&guest.frame(&data(Channel::File, 1, &[1; 300])));
    // The queue is full: the 300 bytes are held, the window stays short.
    assert_eq!(
        link.channel(Channel::File).receive_window_bytes,
        window - 300
    );
    assert_eq!(link.channel(Channel::File).queued_frames, 1);
    let messages: Vec<LinkMessage> = drain(&mut link)
        .into_iter()
        .map(|(_, message)| message)
        .collect();
    assert_eq!(
        messages,
        vec![
            LinkMessage::Opened {
                channel: Channel::File,
                stream: stream(3)
            },
            LinkMessage::WindowUpdate {
                channel: Channel::File,
                credit_bytes: 300
            },
        ]
    );
    assert_eq!(link.channel(Channel::File).receive_window_bytes, window);
}

// ---------------------------------------------------------------------------------------
// Per-stream windows on the ingress and egress channels (protocol version 3)
// ---------------------------------------------------------------------------------------

const FIRST_WINDOW: u64 = super::limits::STREAM_WINDOW_BYTES;
const GROWN_WINDOW: u64 = super::limits::MAX_STREAM_WINDOW_BYTES;

/// Sends `total` bytes of the guest's on egress `id` in frames the channel takes.
fn guest_sends(link: &mut TestLink, guest: &mut Guest, id: u32, total: u64) -> Vec<LinkEvent> {
    let mut events = Vec::new();
    let mut left = total;
    while left > 0 {
        let chunk = left.min(40_000);
        events.extend(link.receive(&guest.frame(&data(
            Channel::Egress,
            id,
            &vec![5; chunk as usize],
        ))));
        left -= chunk;
    }
    events
}

/// The stream credits the link sent, by stream (credit goes ahead of data, last first).
fn stream_credits(link: &mut TestLink) -> Vec<(u32, u32)> {
    let mut credits: Vec<(u32, u32)> = drain(link)
        .into_iter()
        .filter_map(|(_, message)| match message {
            LinkMessage::StreamWindowUpdate {
                stream,
                credit_bytes,
                ..
            } => Some((stream.get(), credit_bytes)),
            _ => None,
        })
        .collect();
    credits.sort_unstable();
    credits
}

fn open_egress(link: &mut TestLink, guest: &mut Guest, id: u32) {
    link.receive(&guest.frame(&egress_open(id)));
    link.send(HostMessage::Opened {
        channel: Channel::Egress,
        stream: stream(id),
    })
    .unwrap();
}

fn all_data(events: &[LinkEvent]) -> bool {
    events
        .iter()
        .all(|event| matches!(event, LinkEvent::Request(GuestRequest::Data { .. })))
}

/// PROVES one stream whose reader stopped holds back no other: stream 1 takes its whole
/// first window and is never consumed, and stream 3 still carries 1 MiB as the host
/// consumes it, credited alone; the host holds stream 1's window and no more of it.
#[test]
fn a_stalled_stream_holds_back_no_other_stream_of_its_channel() {
    let (mut link, _clock, mut guest) = link_with_egress_stream();
    open_egress(&mut link, &mut guest, 3);
    drain(&mut link);
    assert!(all_data(&guest_sends(
        &mut link,
        &mut guest,
        1,
        FIRST_WINDOW
    )));
    let mut carried = 0u64;
    while carried < 1 << 20 {
        let events = guest_sends(&mut link, &mut guest, 3, 16_384);
        assert!(all_data(&events), "{events:?}");
        link.consume_stream(Channel::Egress, stream(3), 16_384)
            .unwrap();
        carried += 16_384;
        for (id, _) in stream_credits(&mut link) {
            assert_eq!(id, 3, "only the consumed stream is credited");
        }
    }
    let summary = link.channel(Channel::Egress);
    assert_eq!(
        summary.buffered_bytes, FIRST_WINDOW,
        "stream 1's bytes, held"
    );
    assert_eq!(summary.closed, None);
}

/// PROVES a guest that sends past a stream's window closes the channel, whatever the
/// channel's other streams hold, and the link stays up.
#[test]
fn guest_data_beyond_a_streams_window_closes_the_channel() {
    let (mut link, _clock, mut guest) = link_with_egress_stream();
    assert!(all_data(&guest_sends(
        &mut link,
        &mut guest,
        1,
        FIRST_WINDOW
    )));
    let events = link.receive(&guest.frame(&data(Channel::Egress, 1, b"x")));
    let reason = RefusalReason::StreamWindowExceeded {
        channel: Channel::Egress,
        stream: stream(1),
        remaining_bytes: 0,
        needed_bytes: 1,
    };
    assert_eq!(reason.code(), "stream_window_exceeded");
    assert_eq!(
        events,
        vec![
            LinkEvent::Refused(Refusal {
                reason,
                effect: RefusalEffect::ChannelClosed {
                    channel: Channel::Egress
                }
            }),
            LinkEvent::ChannelClosed {
                channel: Channel::Egress,
                cause: ChannelCloseCause::StreamWindowExceeded {
                    stream: stream(1),
                    remaining_bytes: 0,
                    needed_bytes: 1
                }
            },
        ]
    );
    assert_eq!(link.phase(), &LinkPhase::Open);
    assert!(matches!(
        &link.receive(&guest.frame(&ping(4)))[..],
        [LinkEvent::Request(GuestRequest::Ping { nonce: 4 })]
    ));
}

/// PROVES the host sends each stream within that stream's credit: a fresh stream has its
/// first window, a second stream its own, the guest's credit raises one stream only, and
/// credit for a stream that is not open is refused, after a cancel refused without charge,
/// and after both ends finished dropped quietly; the egress channel has no channel credit.
#[test]
fn the_host_sends_each_stream_within_its_own_credit() {
    let (mut link, _clock, mut guest) = link_with_egress_stream();
    open_egress(&mut link, &mut guest, 3);
    let egress_data = |id: u32, bytes: usize| HostMessage::Data {
        channel: Channel::Egress,
        stream: stream(id),
        bytes: vec![1; bytes],
    };
    let credit = |id: u32, credit_bytes: u32| LinkMessage::StreamWindowUpdate {
        channel: Channel::Egress,
        stream: stream(id),
        credit_bytes,
    };
    assert_eq!(
        link.stream_send_credit(Channel::Egress, stream(1)),
        FIRST_WINDOW
    );
    assert_eq!(link.stream_send_credit(Channel::File, stream(1)), 0);
    link.send(egress_data(1, 32_768)).unwrap();
    link.send(egress_data(1, 32_768)).unwrap();
    assert_eq!(
        link.send(egress_data(1, 1)),
        Err(SendRefusal::NoStreamCredit {
            channel: Channel::Egress,
            stream: stream(1),
            available_bytes: 0,
            needed_bytes: 1
        })
    );
    assert_eq!(
        link.stream_send_credit(Channel::Egress, stream(3)),
        FIRST_WINDOW
    );
    link.send(egress_data(3, 32_768)).unwrap();
    assert_eq!(
        link.receive(&guest.frame(&credit(1, 100))),
        vec![LinkEvent::Request(GuestRequest::StreamWindowUpdate {
            channel: Channel::Egress,
            stream: stream(1),
            credit_bytes: 100
        })]
    );
    assert_eq!(link.stream_send_credit(Channel::Egress, stream(1)), 100);
    assert_eq!(
        link.stream_send_credit(Channel::Egress, stream(3)),
        FIRST_WINDOW - 32_768
    );
    // Not open: refused and charged.
    let events = link.receive(&guest.frame(&credit(9, 1)));
    assert_eq!(
        refusal(&events).reason,
        RefusalReason::StreamNotOpen {
            channel: Channel::Egress,
            stream: stream(9)
        }
    );
    assert_eq!(link.refusals(), 1);
    // Both ends finished: the credit crossed the finish and is dropped quietly.
    link.send(HostMessage::EndOfStream {
        channel: Channel::Egress,
        stream: stream(3),
    })
    .unwrap();
    link.receive(&guest.frame(&LinkMessage::EndOfStream {
        channel: Channel::Egress,
        stream: stream(3),
    }));
    assert_eq!(link.receive(&guest.frame(&credit(3, 1))), vec![]);
    // Cancelled: refused without charge.
    link.send(HostMessage::Cancel {
        channel: Channel::Egress,
        stream: stream(1),
        cause: CancelCause::Requested,
    })
    .unwrap();
    let events = link.receive(&guest.frame(&credit(1, 1)));
    assert_refused(
        &events,
        RefusalReason::StreamCancelled {
            channel: Channel::Egress,
            stream: stream(1),
        },
        RefusalEffect::FrameDropped,
    );
    assert_eq!(link.refusals(), 1);
    // The egress channel has no channel credit at all.
    let events = link.receive(&guest.frame(&LinkMessage::WindowUpdate {
        channel: Channel::Egress,
        credit_bytes: 1,
    }));
    assert!(matches!(
        refusal(&events).reason,
        RefusalReason::UnknownOperation {
            channel: Channel::Egress,
            ..
        }
    ));
}

/// PROVES the host credits a stream once a quarter of its window is due, grows a stream that
/// consumed its whole first window, bounds the channel's growth by its quota (a stream past
/// it keeps its first window), gives a stream's growth back when it ends, and credits
/// nothing to a stream gone or one the guest ended.
#[test]
fn consumed_bytes_are_credited_to_their_stream_and_fast_streams_grow_within_the_quota() {
    let mut limits = LinkLimits::default();
    // Room for two streams to grow from their first window to the most, not three.
    limits.egress.max_buffered_bytes = 2 * (GROWN_WINDOW - FIRST_WINDOW);
    let (mut link, _clock, mut guest) = open_link(limits);
    for id in [1, 3, 5] {
        open_egress(&mut link, &mut guest, id);
    }
    drain(&mut link);
    assert_eq!(
        link.consume(Channel::Egress, 1),
        Err(ConsumeRefusal::PerStream {
            channel: Channel::Egress
        })
    );
    assert_eq!(
        link.consume_stream(Channel::File, stream(1), 1),
        Err(ConsumeRefusal::NotPerStream {
            channel: Channel::File
        })
    );
    guest_sends(&mut link, &mut guest, 1, 10_000);
    assert_eq!(
        link.consume_stream(Channel::Egress, stream(1), 10_001),
        Err(ConsumeRefusal::StreamMoreThanBuffered {
            channel: Channel::Egress,
            stream: stream(1),
            buffered_bytes: 10_000,
            consumed_bytes: 10_001
        })
    );
    link.consume_stream(Channel::Egress, stream(1), 10_000)
        .unwrap();
    assert_eq!(
        stream_credits(&mut link),
        vec![],
        "less than a quarter of the window is due"
    );
    guest_sends(&mut link, &mut guest, 1, FIRST_WINDOW - 10_000);
    link.consume_stream(Channel::Egress, stream(1), (FIRST_WINDOW - 10_000) as u32)
        .unwrap();
    assert_eq!(
        stream_credits(&mut link),
        vec![(1, GROWN_WINDOW as u32)],
        "a whole first window consumed: grown"
    );
    for id in [3, 5] {
        guest_sends(&mut link, &mut guest, id, FIRST_WINDOW);
        link.consume_stream(Channel::Egress, stream(id), FIRST_WINDOW as u32)
            .unwrap();
    }
    assert_eq!(
        stream_credits(&mut link),
        vec![(3, GROWN_WINDOW as u32), (5, FIRST_WINDOW as u32)],
        "the third stream past the quota keeps its first window"
    );
    // Stream 1 ends: its growth comes back and stream 5 grows at its next credit.
    link.send(HostMessage::Cancel {
        channel: Channel::Egress,
        stream: stream(1),
        cause: CancelCause::Requested,
    })
    .unwrap();
    drain(&mut link);
    guest_sends(&mut link, &mut guest, 5, 20_000);
    link.consume_stream(Channel::Egress, stream(5), 20_000)
        .unwrap();
    assert_eq!(
        stream_credits(&mut link),
        vec![(5, (GROWN_WINDOW - FIRST_WINDOW + 20_000) as u32)]
    );
    // Bytes of a stream gone need no credit.
    assert_eq!(link.consume_stream(Channel::Egress, stream(1), 5), Ok(()));
    // Nothing is credited for a stream the guest ended.
    guest_sends(&mut link, &mut guest, 3, 30_000);
    link.receive(&guest.frame(&LinkMessage::EndOfStream {
        channel: Channel::Egress,
        stream: stream(3),
    }));
    link.consume_stream(Channel::Egress, stream(3), 30_000)
        .unwrap();
    assert_eq!(stream_credits(&mut link), vec![]);
}

/// PROVES a stream's credit that finds the channel's queue full is not lost: it goes out
/// once a frame left the queue.
#[test]
fn stream_credit_that_finds_the_queue_full_goes_out_with_the_next_frame() {
    let mut limits = LinkLimits::default();
    limits.egress.max_queued_frames = 1;
    let (mut link, _clock, mut guest) = open_link(limits);
    open_egress(&mut link, &mut guest, 1);
    drain(&mut link);
    open_egress(&mut link, &mut guest, 3);
    assert_eq!(
        link.channel(Channel::Egress).queued_frames,
        1,
        "stream 3's answer fills the queue"
    );
    guest_sends(&mut link, &mut guest, 1, 20_000);
    link.consume_stream(Channel::Egress, stream(1), 20_000)
        .unwrap();
    assert_eq!(
        link.channel(Channel::Egress).queued_frames,
        1,
        "the credit waits"
    );
    let messages: Vec<LinkMessage> = drain(&mut link)
        .into_iter()
        .map(|(_, message)| message)
        .collect();
    assert_eq!(
        messages,
        vec![
            LinkMessage::Opened {
                channel: Channel::Egress,
                stream: stream(3)
            },
            LinkMessage::StreamWindowUpdate {
                channel: Channel::Egress,
                stream: stream(1),
                credit_bytes: 20_000
            },
        ]
    );
}
