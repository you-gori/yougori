//! Test fakes: a scripted guest end that seals its frames with the guest's key and reads
//! the host's, a real `sandbox::link` host link between the two, a real file protocol
//! dispatcher over the real file service on a temporary root, the CORE-05 port fakes, and
//! a body issuer that seals honest or deliberately wrong grants.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::Value;

use super::*;
use crate::foundation::coordination::VmInstanceId;
use crate::foundation::ids::{
    digest, AuthorizationEpoch, Clock, ContentKey, ExecutionCategory, ManualClock, MonotonicTime,
    OperationId, SandboxBootGeneration, TrustScope,
};
use crate::foundation::transfer::fakes::{
    parent, tenant, test_key, FakeAuthority, FakeByteLedger, FakeExtents, FakeProgress, EPOCH,
    SESSION,
};
use crate::foundation::transfer::{
    Direction, Endpoint, EnvelopeFields, ObjectGrant, SealedEnvelope, StopBounds, TransferEnvelope,
    TransferKey, TransferPorts, TransferScope,
};
use crate::sandbox::link::{
    encode_frame, BootstrapSecret, CancelCause, Channel, DecodeStep, FileMode, FrameDecoder,
    GrantHandle, Hello, HostLink, LinkBinding, LinkEvent, LinkLimits, LinkMessage, LinkName,
    OpenRefusalCause, Operation, Sender, StreamId, StreamOpen, PROTOCOL_VERSION,
};
use crate::sandbox_contract::file_protocol::{
    ChannelLimits, FileDispatcher, GuestOperation, GuestRequest, RequestId,
};
use crate::sandbox_contract::files::{
    FileGrant, FileOperation, FileQuota, FileService, GrantMode, GrantedRoot, GuestName,
};

pub const BOOT: u64 = 3;
pub const GRANT: GrantHandle = GrantHandle(41);
pub const SECRET: &[u8] = b"host secret beside the root";
pub const SECOND: Duration = Duration::from_secs(1);
pub const HOUR: Duration = Duration::from_secs(3_600);

pub fn at(since_zero: Duration) -> MonotonicTime {
    MonotonicTime::ZERO.saturating_add(since_zero)
}

pub fn vm() -> VmInstanceId {
    VmInstanceId::new(digest(
        "yougori/test/guest-files/vm/v1",
        &[b"vm-under-test"],
    ))
}

pub fn other_vm() -> VmInstanceId {
    VmInstanceId::new(digest("yougori/test/guest-files/vm/v1", &[b"another-vm"]))
}

pub fn boot() -> SandboxBootGeneration {
    SandboxBootGeneration::new(BOOT)
}

pub fn other_boot() -> SandboxBootGeneration {
    SandboxBootGeneration::new(BOOT + 1)
}

pub fn scope() -> TrustScope {
    TrustScope::named(ExecutionCategory::VmSandbox, "sandbox-a")
}

pub fn other_scope() -> TrustScope {
    TrustScope::named(ExecutionCategory::VmSandbox, "sandbox-b")
}

pub fn stream(id: u32) -> StreamId {
    StreamId::new(id).unwrap()
}

pub fn id(value: u64) -> RequestId {
    RequestId::new(value)
}

pub fn name(text: &str) -> GuestName {
    GuestName::parse(text).unwrap()
}

pub fn entry(text: &str) -> LinkName {
    LinkName::new(text).unwrap()
}

/// The entry a create or write of `content` is opened with.
pub fn content_entry(content: &[u8]) -> LinkName {
    Declaration::Content {
        content: ContentKey::of(content),
    }
    .entry()
    .unwrap()
}

/// `length` bytes that differ from part to part.
pub fn pattern(length: usize, seed: u8) -> Vec<u8> {
    (0..length)
        .map(|index| (index % 251) as u8 ^ seed)
        .collect()
}

pub fn identity() -> ChannelIdentity {
    ChannelIdentity {
        vm: vm(),
        boot: boot(),
        scope: scope(),
        tenant: tenant(),
        parent: parent(),
        operation: OperationId::new("op-guest-files-channel").unwrap(),
    }
}

fn secret() -> BootstrapSecret {
    let mut bytes = [0u8; 32];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = (index as u8).wrapping_mul(17).wrapping_add(11);
    }
    BootstrapSecret::new(&bytes).unwrap()
}

pub fn binding(instance: VmInstanceId, generation: SandboxBootGeneration) -> LinkBinding {
    LinkBinding::new(instance, generation, secret())
}

/// The longest message a data frame of the default link carries.
pub fn room() -> u64 {
    message_room(&LinkLimits::default())
}

/// A dispatcher for `scope` over `root`, granting every operation until an hour from the
/// clock's zero on the test clock session.
pub fn dispatcher(
    root: &Path,
    clock: &Arc<ManualClock>,
    scope: TrustScope,
    limits: ChannelLimits,
) -> FileDispatcher<Arc<ManualClock>> {
    let root = GrantedRoot::open(root).unwrap();
    let operations: BTreeSet<FileOperation> = [
        FileOperation::Read,
        FileOperation::List,
        FileOperation::Create,
        FileOperation::Write,
        FileOperation::Delete,
        FileOperation::Rename,
        FileOperation::SetExecutable,
    ]
    .into_iter()
    .collect();
    let grant = FileGrant::new(
        root.handle(),
        GrantMode::QuarantineOutput,
        operations,
        scope,
        SESSION,
        at(HOUR),
        FileQuota {
            max_total_bytes: 1 << 26,
            max_entries: 1_000,
            max_file_bytes: 1 << 25,
        },
    )
    .unwrap();
    FileDispatcher::new(
        FileService::new(grant, root).unwrap(),
        scope,
        Arc::clone(clock),
        SESSION,
        limits,
    )
    .unwrap()
}

/// How the issuer answers.
#[derive(Clone)]
pub enum Issue {
    /// The grant asked for: the declared object whole, a budget of its length, 1 MiB in
    /// flight, 10 s per chunk, expiring an hour from zero.
    Honest,
    Refuse(AuthorityRefusal),
    /// An honest grant naming another source.
    Source(Endpoint),
    /// An honest grant for another object of the same length.
    Object(ContentKey),
    /// An honest grant sealed with another key.
    OtherKey,
    /// An honest grant with this budget.
    Budget(u64),
    /// The envelope issued last, again.
    Replay,
}

/// The host's issuer of body grants, scripted.
pub struct Issuer {
    pub issue: Mutex<Issue>,
    pub requests: Mutex<Vec<BodyRequest>>,
    last: Mutex<Option<SealedEnvelope>>,
}

impl Issuer {
    pub fn new() -> Self {
        Self {
            issue: Mutex::new(Issue::Honest),
            requests: Mutex::new(Vec::new()),
            last: Mutex::new(None),
        }
    }

    pub fn set(&self, issue: Issue) {
        *self.issue.lock().unwrap() = issue;
    }

    pub fn requests(&self) -> Vec<BodyRequest> {
        self.requests.lock().unwrap().clone()
    }
}

impl Default for Issuer {
    fn default() -> Self {
        Self::new()
    }
}

impl BodyAuthority for Issuer {
    fn authorize(&self, request: &BodyRequest) -> Result<SealedEnvelope, AuthorityRefusal> {
        self.requests.lock().unwrap().push(request.clone());
        let issue = self.issue.lock().unwrap().clone();
        let mut fields = EnvelopeFields {
            operation: request.operation.clone(),
            tenant: request.tenant.clone(),
            parent: request.parent.clone(),
            epoch: EPOCH,
            direction: Direction::Download,
            source: request.source.clone(),
            recipient: request.recipient.clone(),
            credential: None,
            scope: TransferScope::single(
                request.object,
                ObjectGrant::whole(request.length_bytes).unwrap(),
            ),
            budget_bytes: request.length_bytes,
            stop_bounds: StopBounds {
                max_in_flight_bytes: 1 << 20,
                max_chunk_duration: 10 * SECOND,
            },
            clock: SESSION,
            expires_at: at(HOUR),
        };
        let mut key = test_key();
        match issue {
            Issue::Honest => {}
            Issue::Refuse(refusal) => return Err(refusal),
            Issue::Source(source) => fields.source = source,
            Issue::Object(object) => {
                fields.scope =
                    TransferScope::single(object, ObjectGrant::whole(request.length_bytes).unwrap())
            }
            Issue::OtherKey => key = TransferKey::from_bytes(&[9u8; 32]).unwrap(),
            Issue::Budget(budget_bytes) => fields.budget_bytes = budget_bytes,
            Issue::Replay => {
                if let Some(last) = self.last.lock().unwrap().clone() {
                    return Ok(last);
                }
            }
        }
        let sealed = key.seal(TransferEnvelope::new(fields).unwrap());
        *self.last.lock().unwrap() = Some(sealed.clone());
        Ok(sealed)
    }
}

/// The guest end of a link: it seals its frames with the guest's key and consecutive
/// sequences, and reads the host's frames after checking their tags.
pub struct GuestEnd {
    binding: LinkBinding,
    sequence: u64,
    decoder: FrameDecoder,
}

impl GuestEnd {
    pub fn new(instance: VmInstanceId, generation: SandboxBootGeneration) -> Self {
        Self {
            binding: binding(instance, generation),
            sequence: 0,
            decoder: FrameDecoder::new(LinkLimits::default().max_frame_bytes),
        }
    }

    pub fn frame(&mut self, message: &LinkMessage) -> Vec<u8> {
        self.sequence += 1;
        encode_frame(&self.binding, Sender::Guest, self.sequence, message).unwrap()
    }

    /// The host's messages in `bytes`; every tag must be the host's.
    pub fn read(&mut self, bytes: &[u8]) -> Vec<LinkMessage> {
        self.decoder
            .push(bytes, MonotonicTime::ZERO)
            .into_iter()
            .map(|step| match step {
                DecodeStep::Frame(raw) => {
                    assert!(self.binding.verify(
                        Sender::Host,
                        &raw.header_bytes,
                        &raw.payload,
                        &raw.tag
                    ));
                    let channel = raw.header.channel;
                    let operation = Operation::decode(channel, raw.header.operation_code).unwrap();
                    LinkMessage::decode(
                        channel,
                        operation,
                        raw.header.stream,
                        &raw.payload,
                        usize::MAX,
                    )
                    .unwrap()
                }
                DecodeStep::Refused(refusal) => panic!("the host sent a bad frame: {refusal}"),
            })
            .collect()
    }
}

/// The host's transfer key and ports over the CORE-05 fakes, with `issuer` for bodies.
pub fn transfers(
    clock: &Arc<ManualClock>,
    authority: &Arc<FakeAuthority>,
    ledger: &Arc<FakeByteLedger>,
    progress: &Arc<FakeProgress>,
    issuer: &Arc<Issuer>,
) -> BodyTransfers {
    BodyTransfers {
        key: test_key(),
        ports: TransferPorts {
            clock: Arc::clone(clock) as Arc<dyn Clock>,
            clock_session: SESSION,
            authority: authority.clone(),
            budget: ledger.clone(),
            extents: Arc::new(FakeExtents::default()),
            progress: progress.clone(),
        },
        authority: issuer.clone(),
    }
}

/// How a rig is set up.
pub struct Setup {
    pub limits: FilesLimits,
    /// The credit the guest grants on the file channel after its hello.
    pub credit: u32,
}

impl Default for Setup {
    fn default() -> Self {
        Self {
            limits: FilesLimits::default(),
            credit: 16 << 20,
        }
    }
}

/// A guest end, a real host link, the adapter over a real dispatcher and file service on a
/// fresh root with a secret beside it, and the CORE-05 fakes. The clock starts at one
/// second. Fields drop in order, so the adapter and its file service close their handles
/// before the temporary directory goes.
pub struct Rig {
    pub clock: Arc<ManualClock>,
    pub link: HostLink<Arc<ManualClock>>,
    pub guest: GuestEnd,
    pub files: GuestFiles<Arc<ManualClock>>,
    pub authority: Arc<FakeAuthority>,
    pub ledger: Arc<FakeByteLedger>,
    pub progress: Arc<FakeProgress>,
    pub issuer: Arc<Issuer>,
    /// Link events that are not the adapter's.
    pub other_events: Vec<LinkEvent>,
    pub dir: tempfile::TempDir,
}

pub type Events = Vec<FilesEvent>;

impl Default for Rig {
    fn default() -> Self {
        Self::new()
    }
}

impl Rig {
    pub fn new() -> Self {
        Self::with(Setup::default())
    }

    pub fn with(setup: Setup) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("root");
        fs::create_dir(&root).unwrap();
        fs::write(dir.path().join("secret.txt"), SECRET).unwrap();
        let clock = Arc::new(ManualClock::new(at(SECOND)));
        let authority = Arc::new(FakeAuthority::default());
        authority.grant(&parent(), EPOCH, at(24 * HOUR));
        let ledger = Arc::new(FakeByteLedger::new(1 << 40));
        let progress = Arc::new(FakeProgress::default());
        let issuer = Arc::new(Issuer::new());
        let transfers = transfers(&clock, &authority, &ledger, &progress, &issuer);
        let mut files =
            GuestFiles::new(identity(), LinkLimits::default(), transfers, setup.limits).unwrap();
        files
            .add_grant(
                GRANT,
                dispatcher(
                    &root,
                    &clock,
                    scope(),
                    channel_limits(&LinkLimits::default()),
                ),
            )
            .unwrap();
        let link = HostLink::new(
            binding(vm(), boot()),
            LinkLimits::default(),
            Arc::clone(&clock),
        )
        .unwrap();
        let mut rig = Self {
            clock,
            link,
            guest: GuestEnd::new(vm(), boot()),
            files,
            authority,
            ledger,
            progress,
            issuer,
            other_events: Vec::new(),
            dir,
        };
        let events = rig.greet(setup.credit);
        assert!(events.is_empty(), "{events:?}");
        rig
    }

    /// The guest says hello and grants `credit` on the file channel; the adapter's events
    /// on the credit.
    fn greet(&mut self, credit: u32) -> Events {
        let hello = LinkMessage::Hello(Hello {
            guest_version: PROTOCOL_VERSION,
            agent_build: digest("yougori/test/guest-files/agent/v1", &[b"agent"]),
            claimed_vm: None,
            claimed_boot: None,
        });
        assert!(self.send(hello).is_empty());
        let events = if credit > 0 {
            self.credit(credit)
        } else {
            Vec::new()
        };
        self.drain();
        events
    }

    /// A new link of the same instance and boot, as after the transport reconnected; the
    /// adapter's events on the guest's credit.
    pub fn reconnect(&mut self, credit: u32) -> Events {
        self.link = HostLink::new(
            binding(vm(), boot()),
            LinkLimits::default(),
            Arc::clone(&self.clock),
        )
        .unwrap();
        self.guest = GuestEnd::new(vm(), boot());
        self.greet(credit)
    }

    /// The transport loses the link; the adapter is given the link's closing events.
    pub fn lose_link(&mut self) -> Events {
        let closing = self.link.peer_closed();
        let mut events = Vec::new();
        for event in closing {
            events.extend(self.files.handle(&mut self.link, event).unwrap());
        }
        events
    }

    pub fn root(&self) -> std::path::PathBuf {
        self.dir.path().join("root")
    }

    /// Sends `message` from the guest; the link's file events go to the adapter.
    pub fn send(&mut self, message: LinkMessage) -> Events {
        let frame = self.guest.frame(&message);
        let mut events = Vec::new();
        for event in self.link.receive(&frame) {
            if GuestFiles::<Arc<ManualClock>>::is_file_event(&event) {
                events.extend(self.files.handle(&mut self.link, event).unwrap());
            } else {
                self.other_events.push(event);
            }
        }
        events
    }

    /// Everything the host queued, as the guest reads it.
    pub fn drain(&mut self) -> Vec<LinkMessage> {
        let mut messages = Vec::new();
        while let Some(frame) = self.link.next_outbound() {
            messages.extend(self.guest.read(&frame));
        }
        messages
    }

    pub fn pump(&mut self) -> Events {
        self.files.pump(&mut self.link).unwrap()
    }

    pub fn credit(&mut self, credit_bytes: u32) -> Events {
        self.send(LinkMessage::WindowUpdate {
            channel: Channel::File,
            credit_bytes,
        })
    }

    pub fn open_with(
        &mut self,
        stream_id: u32,
        grant: GrantHandle,
        entry: LinkName,
        mode: FileMode,
    ) -> Events {
        self.send(LinkMessage::Open {
            stream: stream(stream_id),
            open: StreamOpen::File { grant, entry, mode },
        })
    }

    pub fn open(&mut self, stream_id: u32, entry: LinkName, mode: FileMode) -> Events {
        self.open_with(stream_id, GRANT, entry, mode)
    }

    pub fn data(&mut self, stream_id: u32, bytes: &[u8]) -> Events {
        self.send(LinkMessage::Data {
            channel: Channel::File,
            stream: stream(stream_id),
            bytes: bytes.to_vec(),
        })
    }

    pub fn end(&mut self, stream_id: u32) -> Events {
        self.send(LinkMessage::EndOfStream {
            channel: Channel::File,
            stream: stream(stream_id),
        })
    }

    pub fn cancel(&mut self, stream_id: u32, cause: CancelCause) -> Events {
        self.send(LinkMessage::Cancel {
            channel: Channel::File,
            stream: stream(stream_id),
            cause,
        })
    }

    /// Every message of a request, as the guest encodes it for this link.
    pub fn messages(request: u64, operation: GuestOperation) -> Vec<Vec<u8>> {
        GuestRequest {
            id: id(request),
            operation,
        }
        .encode(room())
        .unwrap()
    }

    /// Sends every message of a request on a stream.
    pub fn request(&mut self, stream_id: u32, request: u64, operation: GuestOperation) -> Events {
        let mut events = Vec::new();
        for message in Self::messages(request, operation) {
            events.extend(self.data(stream_id, &message));
        }
        events
    }

    /// Opens a stream declared for `operation` and sends the whole request on it.
    pub fn call(&mut self, stream_id: u32, request: u64, operation: GuestOperation) -> Events {
        let kind = OperationKind::of(&operation);
        let (entry, mode) = match &operation {
            GuestOperation::Create { content, .. } | GuestOperation::Write { content, .. } => {
                (content_entry(content), FileMode::Write)
            }
            _ => (LinkName::new(kind.name()).unwrap(), kind.mode()),
        };
        let mut events = self.open(stream_id, entry, mode);
        events.extend(self.request(stream_id, request, operation));
        events
    }
}

/// The data a stream carried, message by message.
pub fn data_on(messages: &[LinkMessage], stream_id: u32) -> Vec<Vec<u8>> {
    messages
        .iter()
        .filter_map(|message| match message {
            LinkMessage::Data {
                channel: Channel::File,
                stream: on,
                bytes,
            } if on.get() == stream_id => Some(bytes.clone()),
            _ => None,
        })
        .collect()
}

/// One response message: its header and its content.
pub fn parse(message: &[u8]) -> (Value, Vec<u8>) {
    let end = message.iter().position(|byte| *byte == b'\n').unwrap();
    (
        serde_json::from_slice(&message[..end]).unwrap(),
        message[end + 1..].to_vec(),
    )
}

/// The outcome of the answer a stream carried.
pub fn outcome(messages: &[LinkMessage], stream_id: u32) -> Value {
    let data = data_on(messages, stream_id);
    let first = data
        .first()
        .unwrap_or_else(|| panic!("no answer on {stream_id}"));
    parse(first).0["outcome"].clone()
}

/// The content of the answer a stream carried, from all its parts.
pub fn content(messages: &[LinkMessage], stream_id: u32) -> Vec<u8> {
    data_on(messages, stream_id)
        .iter()
        .flat_map(|message| parse(message).1)
        .collect()
}

pub fn ended(messages: &[LinkMessage], stream_id: u32) -> bool {
    messages.iter().any(|message| {
        matches!(message, LinkMessage::EndOfStream { channel: Channel::File, stream: on }
            if on.get() == stream_id)
    })
}

pub fn opened(messages: &[LinkMessage], stream_id: u32) -> bool {
    messages.iter().any(|message| {
        matches!(message, LinkMessage::Opened { channel: Channel::File, stream: on }
            if on.get() == stream_id)
    })
}

pub fn cancel_of(messages: &[LinkMessage], stream_id: u32) -> Option<CancelCause> {
    messages.iter().find_map(|message| match message {
        LinkMessage::Cancel {
            channel: Channel::File,
            stream: on,
            cause,
        } if on.get() == stream_id => Some(*cause),
        _ => None,
    })
}

pub fn open_refused(messages: &[LinkMessage], stream_id: u32) -> Option<OpenRefusalCause> {
    messages.iter().find_map(|message| match message {
        LinkMessage::OpenRefused {
            channel: Channel::File,
            stream: on,
            cause,
        } if on.get() == stream_id => Some(*cause),
        _ => None,
    })
}

/// The refusals among `events`.
pub fn refusals(events: &[FilesEvent]) -> Vec<FilesRefusal> {
    events
        .iter()
        .filter_map(|event| match event {
            FilesEvent::Refused { refusal, .. } => Some(refusal.clone()),
            _ => None,
        })
        .collect()
}

/// The body phases among `events`.
pub fn phases(events: &[FilesEvent]) -> Vec<BodyPhase> {
    events
        .iter()
        .filter_map(|event| match event {
            FilesEvent::Body { phase, .. } => Some(phase.clone()),
            _ => None,
        })
        .collect()
}

/// A grant handle the channel does not hold, kept apart from [`GRANT`].
pub const STRANGER: GrantHandle = GrantHandle(99);

/// The epoch the fake parent moves to on revocation.
pub fn revoked_epoch() -> AuthorizationEpoch {
    EPOCH.next().unwrap()
}
