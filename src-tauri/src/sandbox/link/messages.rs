//! The typed messages of every operation, their payload schemas and codecs, the host's
//! sendable set and the closed set of guest requests a later broker authorizes (§3.1 relay
//! row line 2045: "parse bounded frames and forward typed requests"; §2.6 line 2004: "a
//! guest-controlled message cannot select a host executable, arbitrary host path or
//! privileged endpoint"). No message carries a path, an executable, a URL or an address:
//! files are named by a host-issued grant handle and one entry name, destinations and
//! listeners by a name the destinations contract resolves.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::foundation::events::RevocationReason;
use crate::foundation::ids::{AuthorizationEpoch, Digest};

use super::connection::{Connection, CONNECTION_NONCE_BYTES};
use super::fields::{
    EncodeRefusal, FieldRefusal, FieldSpec, FieldWriter, Fields, LinkName, MAX_TEXT_BYTES,
};
use super::wire::{Channel, Operation, Sender, StreamUse};

/// A stream id: non-zero; odd ids are opened by the guest, even ids by the host, so the
/// two ends never collide.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct StreamId(u32);

impl StreamId {
    pub const fn new(id: u32) -> Option<Self> {
        if id == 0 {
            None
        } else {
            Some(Self(id))
        }
    }

    pub const fn get(self) -> u32 {
        self.0
    }

    /// Who opens streams with this id, by parity.
    pub const fn opener(self) -> Sender {
        if self.0 % 2 == 1 {
            Sender::Guest
        } else {
            Sender::Host
        }
    }
}

impl fmt::Display for StreamId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A host-issued file grant: an opaque handle to a root the file broker holds, never a
/// path (§3.1 file broker row: "granted root handles").
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct GrantHandle(pub u64);

macro_rules! code_enum {
    ($(#[$doc:meta])* $name:ident { $($variant:ident = $code:literal),+ $(,)? }) => {
        $(#[$doc])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
        #[serde(rename_all = "snake_case")]
        pub enum $name {
            $($variant),+
        }

        impl $name {
            pub const fn code(self) -> u8 {
                match self {
                    $(Self::$variant => $code),+
                }
            }

            pub const fn from_code(code: u8) -> Option<Self> {
                match code {
                    $($code => Some(Self::$variant),)+
                    _ => None,
                }
            }
        }
    };
}

code_enum!(
    /// Why a link closes.
    CloseReason {
        Orderly = 1,
        ProtocolViolation = 2,
        TimedOut = 3,
        Revoked = 4,
        Shutdown = 5,
    }
);

code_enum!(
    /// The init stages of §3.3 ("mount verified images, establish the channel, set guest
    /// restrictions, spawn the agent/workload").
    InitStage {
        Mounts = 1,
        Channel = 2,
        Restrictions = 3,
        Agent = 4,
        Workload = 5,
    }
);

code_enum!(
    /// What a guest says about a probe or stage. It is the guest's word (VM-P29).
    ProbeOutcome {
        Passed = 1,
        Failed = 2,
        Skipped = 3,
        Inconclusive = 4,
    }
);

code_enum!(
    /// How a file stream is used.
    FileMode {
        Read = 1,
        Write = 2,
    }
);

code_enum!(
    /// Why an open was refused by the other end.
    OpenRefusalCause {
        NotAuthorized = 1,
        Unavailable = 2,
        QuotaExceeded = 3,
        Unsupported = 4,
    }
);

code_enum!(
    /// Why a stream was cancelled.
    CancelCause {
        Requested = 1,
        TimedOut = 2,
        Revoked = 3,
        QuotaExceeded = 4,
        Failed = 5,
    }
);

/// The wire code of a CORE-06 revocation reason.
pub const fn revocation_reason_code(reason: RevocationReason) -> u8 {
    match reason {
        RevocationReason::UserRequested => 1,
        RevocationReason::PolicyChanged => 2,
        RevocationReason::AuthorizationExpired => 3,
        RevocationReason::SecurityEvent => 4,
        RevocationReason::OwnerReclaimed => 5,
    }
}

pub const fn revocation_reason_from_code(code: u8) -> Option<RevocationReason> {
    match code {
        1 => Some(RevocationReason::UserRequested),
        2 => Some(RevocationReason::PolicyChanged),
        3 => Some(RevocationReason::AuthorizationExpired),
        4 => Some(RevocationReason::SecurityEvent),
        5 => Some(RevocationReason::OwnerReclaimed),
        _ => None,
    }
}

/// The guest's first message. The claimed VM and boot are what the guest believes it
/// was given; they are checked against the host's binding and never used as identity.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Hello {
    pub guest_version: u8,
    /// Digest of the agent build the guest says it runs.
    pub agent_build: Digest,
    pub claimed_vm: Option<Digest>,
    pub claimed_boot: Option<u64>,
}

/// The host's terms, sent after an accepted hello.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct WelcomeTerms {
    pub version: u8,
    pub max_frame_bytes: u32,
    pub idle_timeout_seconds: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct Revoke {
    pub reason: RevocationReason,
    pub authorization_epoch: AuthorizationEpoch,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct Shutdown {
    pub grace_seconds: u32,
}

/// A guest report about one init stage.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct InitReport {
    pub stage: InitStage,
    pub outcome: ProbeOutcome,
    pub detail: String,
    pub claimed_vm: Option<Digest>,
}

/// A guest report about one probe.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ProbeResult {
    pub probe: LinkName,
    pub outcome: ProbeOutcome,
    pub detail: String,
}

/// A guest report that every probe passed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct AllProbesPassed {
    pub probe_count: u32,
}

/// What an open names, by channel.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "open", rename_all = "snake_case")]
pub enum StreamOpen {
    /// Run the argv bound into the guest's authenticated image declaration.
    ImageEntrypoint,
    Terminal {
        columns: u16,
        rows: u16,
    },
    File {
        grant: GrantHandle,
        entry: LinkName,
        mode: FileMode,
    },
    /// A published listener name inside the guest.
    Ingress {
        listener: LinkName,
    },
    /// A destination name for the destinations contract to resolve; never an address.
    Egress {
        destination: LinkName,
    },
}

impl StreamOpen {
    pub const fn channel(&self) -> Channel {
        match self {
            Self::Terminal { .. } | Self::ImageEntrypoint => Channel::Terminal,
            Self::File { .. } => Channel::File,
            Self::Ingress { .. } => Channel::Ingress,
            Self::Egress { .. } => Channel::Egress,
        }
    }
}

/// Why a payload was refused after the frame was authenticated.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "payload_refusal", rename_all = "snake_case")]
pub enum PayloadRefusal {
    Field(FieldRefusal),
    /// A stream operation with stream id zero.
    StreamIdRequired,
    /// A channel-level operation with a non-zero stream id.
    StreamIdForbidden {
        stream: u32,
    },
}

impl PayloadRefusal {
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Field(refusal) => refusal.code(),
            Self::StreamIdRequired => "stream_id_required",
            Self::StreamIdForbidden { .. } => "stream_id_forbidden",
        }
    }
}

impl fmt::Display for PayloadRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Field(refusal) => fmt::Display::fmt(refusal, f),
            Self::StreamIdRequired => f.write_str("the operation needs a stream id"),
            Self::StreamIdForbidden { stream } => {
                write!(
                    f,
                    "the operation is channel-level but names stream {stream}"
                )
            }
        }
    }
}

impl std::error::Error for PayloadRefusal {}

impl From<FieldRefusal> for PayloadRefusal {
    fn from(refusal: FieldRefusal) -> Self {
        Self::Field(refusal)
    }
}

/// Every message of the protocol, whichever end sends it. The host's sendable subset is
/// [`HostMessage`]; what the host accepts from the guest becomes a [`GuestRequest`] or a
/// report.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "message", rename_all = "snake_case")]
pub enum LinkMessage {
    /// The host's first message on a challenged link; the link issues it itself.
    Challenge {
        connection: Connection,
    },
    Hello(Hello),
    Welcome(WelcomeTerms),
    Ping {
        nonce: u64,
    },
    Pong {
        nonce: u64,
    },
    Revoke(Revoke),
    Shutdown(Shutdown),
    InitReport(InitReport),
    ProbeResult(ProbeResult),
    AllProbesPassed(AllProbesPassed),
    Close {
        reason: CloseReason,
    },
    WindowUpdate {
        channel: Channel,
        credit_bytes: u32,
    },
    /// Credit for one ingress or egress stream (version 3).
    StreamWindowUpdate {
        channel: Channel,
        stream: StreamId,
        credit_bytes: u32,
    },
    Open {
        stream: StreamId,
        open: StreamOpen,
    },
    Opened {
        channel: Channel,
        stream: StreamId,
    },
    OpenRefused {
        channel: Channel,
        stream: StreamId,
        cause: OpenRefusalCause,
    },
    Data {
        channel: Channel,
        stream: StreamId,
        bytes: Vec<u8>,
    },
    EndOfStream {
        channel: Channel,
        stream: StreamId,
    },
    Cancel {
        channel: Channel,
        stream: StreamId,
        cause: CancelCause,
    },
    Resize {
        stream: StreamId,
        columns: u16,
        rows: u16,
    },
    Exit {
        stream: StreamId,
        code: i32,
    },
}

const TAG_1: u8 = 1;
const TAG_2: u8 = 2;
const TAG_3: u8 = 3;
const TAG_4: u8 = 4;

const NO_FIELDS: [FieldSpec; 0] = [];
const HELLO: [FieldSpec; 4] = [
    FieldSpec::required(TAG_1),
    FieldSpec::required(TAG_2),
    FieldSpec::optional(TAG_3),
    FieldSpec::optional(TAG_4),
];
const WELCOME: [FieldSpec; 3] = [
    FieldSpec::required(TAG_1),
    FieldSpec::required(TAG_2),
    FieldSpec::required(TAG_3),
];
const ONE: [FieldSpec; 1] = [FieldSpec::required(TAG_1)];
const TWO: [FieldSpec; 2] = [FieldSpec::required(TAG_1), FieldSpec::required(TAG_2)];
const TERMINAL: [FieldSpec; 3] = [
    FieldSpec::required(TAG_1),
    FieldSpec::required(TAG_2),
    FieldSpec::optional(TAG_3),
];
const THREE: [FieldSpec; 3] = [
    FieldSpec::required(TAG_1),
    FieldSpec::required(TAG_2),
    FieldSpec::required(TAG_3),
];
const INIT_REPORT: [FieldSpec; 4] = [
    FieldSpec::required(TAG_1),
    FieldSpec::required(TAG_2),
    FieldSpec::required(TAG_3),
    FieldSpec::optional(TAG_4),
];

impl LinkMessage {
    pub const fn channel(&self) -> Channel {
        match self {
            Self::Challenge { .. }
            | Self::Hello(_)
            | Self::Welcome(_)
            | Self::Ping { .. }
            | Self::Pong { .. }
            | Self::Revoke(_)
            | Self::Shutdown(_)
            | Self::InitReport(_)
            | Self::ProbeResult(_)
            | Self::AllProbesPassed(_)
            | Self::Close { .. } => Channel::Control,
            Self::WindowUpdate { channel, .. }
            | Self::StreamWindowUpdate { channel, .. }
            | Self::Opened { channel, .. }
            | Self::OpenRefused { channel, .. }
            | Self::Data { channel, .. }
            | Self::EndOfStream { channel, .. }
            | Self::Cancel { channel, .. } => *channel,
            Self::Open { open, .. } => open.channel(),
            Self::Resize { .. } | Self::Exit { .. } => Channel::Terminal,
        }
    }

    pub const fn operation(&self) -> Operation {
        match self {
            Self::Challenge { .. } => Operation::Challenge,
            Self::Hello(_) => Operation::Hello,
            Self::Welcome(_) => Operation::Welcome,
            Self::Ping { .. } => Operation::Ping,
            Self::Pong { .. } => Operation::Pong,
            Self::Revoke(_) => Operation::Revoke,
            Self::Shutdown(_) => Operation::Shutdown,
            Self::InitReport(_) => Operation::InitReport,
            Self::ProbeResult(_) => Operation::ProbeResult,
            Self::AllProbesPassed(_) => Operation::AllProbesPassed,
            Self::Close { .. } => Operation::Close,
            Self::WindowUpdate { .. } => Operation::WindowUpdate,
            Self::StreamWindowUpdate { .. } => Operation::StreamWindowUpdate,
            Self::Open { .. } => Operation::Open,
            Self::Opened { .. } => Operation::Opened,
            Self::OpenRefused { .. } => Operation::OpenRefused,
            Self::Data { .. } => Operation::Data,
            Self::EndOfStream { .. } => Operation::EndOfStream,
            Self::Cancel { .. } => Operation::Cancel,
            Self::Resize { .. } => Operation::Resize,
            Self::Exit { .. } => Operation::Exit,
        }
    }

    /// The stream the message names, or `None` for channel-level messages.
    pub const fn stream(&self) -> Option<StreamId> {
        match self {
            Self::StreamWindowUpdate { stream, .. }
            | Self::Open { stream, .. }
            | Self::Opened { stream, .. }
            | Self::OpenRefused { stream, .. }
            | Self::Data { stream, .. }
            | Self::EndOfStream { stream, .. }
            | Self::Cancel { stream, .. }
            | Self::Resize { stream, .. }
            | Self::Exit { stream, .. } => Some(*stream),
            _ => None,
        }
    }

    /// The stream id as the header carries it.
    pub const fn stream_code(&self) -> u32 {
        match self.stream() {
            Some(stream) => stream.get(),
            None => 0,
        }
    }

    /// The payload bytes of the message.
    pub fn encode_payload(&self) -> Result<Vec<u8>, EncodeRefusal> {
        let writer = FieldWriter::new();
        let writer = match self {
            Self::Challenge { connection } => writer.bytes(TAG_1, connection.as_bytes())?,
            Self::Hello(hello) => {
                let mut writer = writer
                    .u8(TAG_1, hello.guest_version)
                    .digest(TAG_2, &hello.agent_build);
                if let Some(vm) = &hello.claimed_vm {
                    writer = writer.digest(TAG_3, vm);
                }
                if let Some(boot) = hello.claimed_boot {
                    writer = writer.u64(TAG_4, boot);
                }
                writer
            }
            Self::Welcome(terms) => writer
                .u8(TAG_1, terms.version)
                .u32(TAG_2, terms.max_frame_bytes)
                .u32(TAG_3, terms.idle_timeout_seconds),
            Self::Ping { nonce } | Self::Pong { nonce } => writer.u64(TAG_1, *nonce),
            Self::Revoke(revoke) => writer
                .u8(TAG_1, revocation_reason_code(revoke.reason))
                .u64(TAG_2, revoke.authorization_epoch.get()),
            Self::Shutdown(shutdown) => writer.u32(TAG_1, shutdown.grace_seconds),
            Self::InitReport(report) => {
                let mut writer = writer
                    .u8(TAG_1, report.stage.code())
                    .u8(TAG_2, report.outcome.code())
                    .text(TAG_3, &report.detail)?;
                if let Some(vm) = &report.claimed_vm {
                    writer = writer.digest(TAG_4, vm);
                }
                writer
            }
            Self::ProbeResult(result) => writer
                .text(TAG_1, result.probe.as_str())?
                .u8(TAG_2, result.outcome.code())
                .text(TAG_3, &result.detail)?,
            Self::AllProbesPassed(passed) => writer.u32(TAG_1, passed.probe_count),
            Self::Close { reason } => writer.u8(TAG_1, reason.code()),
            Self::WindowUpdate { credit_bytes, .. }
            | Self::StreamWindowUpdate { credit_bytes, .. } => writer.u32(TAG_1, *credit_bytes),
            Self::Open { open, .. } => match open {
                StreamOpen::ImageEntrypoint => writer.u16(TAG_1, 0).u16(TAG_2, 0).u8(TAG_3, 1),
                StreamOpen::Terminal { columns, rows } => {
                    writer.u16(TAG_1, *columns).u16(TAG_2, *rows)
                }
                StreamOpen::File { grant, entry, mode } => writer
                    .u64(TAG_1, grant.0)
                    .text(TAG_2, entry.as_str())?
                    .u8(TAG_3, mode.code()),
                StreamOpen::Ingress { listener } => writer.text(TAG_1, listener.as_str())?,
                StreamOpen::Egress { destination } => writer.text(TAG_1, destination.as_str())?,
            },
            Self::Opened { .. } | Self::EndOfStream { .. } => writer,
            Self::OpenRefused { cause, .. } => writer.u8(TAG_1, cause.code()),
            Self::Data { bytes, .. } => writer.bytes(TAG_1, bytes)?,
            Self::Cancel { cause, .. } => writer.u8(TAG_1, cause.code()),
            Self::Resize { columns, rows, .. } => writer.u16(TAG_1, *columns).u16(TAG_2, *rows),
            Self::Exit { code, .. } => writer.i32(TAG_1, *code),
        };
        Ok(writer.finish())
    }

    /// Decodes the payload of `operation` on `channel` with header stream id `stream`.
    /// `max_data_bytes` bounds a data chunk. The operation must exist on the channel
    /// (callers resolve it with [`Operation::decode`] first).
    pub fn decode(
        channel: Channel,
        operation: Operation,
        stream: u32,
        payload: &[u8],
        max_data_bytes: usize,
    ) -> Result<Self, PayloadRefusal> {
        let stream_id = match (operation.stream_use(), StreamId::new(stream)) {
            (StreamUse::None, None) => None,
            (StreamUse::None, Some(_)) => return Err(PayloadRefusal::StreamIdForbidden { stream }),
            (StreamUse::Required, None) => return Err(PayloadRefusal::StreamIdRequired),
            (StreamUse::Required, Some(id)) => Some(id),
        };
        let required = || stream_id.ok_or(PayloadRefusal::StreamIdRequired);
        let message = match operation {
            Operation::Challenge => {
                let fields = Fields::parse(payload, &ONE)?;
                let value = fields.bytes(TAG_1, CONNECTION_NONCE_BYTES)?;
                let bytes = <[u8; CONNECTION_NONCE_BYTES]>::try_from(value).map_err(|_| {
                    FieldRefusal::WrongLength {
                        tag: TAG_1,
                        expected_bytes: CONNECTION_NONCE_BYTES,
                        found_bytes: value.len(),
                    }
                })?;
                Self::Challenge {
                    connection: Connection::from_bytes(bytes),
                }
            }
            Operation::Hello => {
                let fields = Fields::parse(payload, &HELLO)?;
                Self::Hello(Hello {
                    guest_version: fields.u8(TAG_1)?,
                    agent_build: fields.digest(TAG_2)?,
                    claimed_vm: fields.optional_digest(TAG_3)?,
                    claimed_boot: fields.optional_u64(TAG_4)?,
                })
            }
            Operation::Welcome => {
                let fields = Fields::parse(payload, &WELCOME)?;
                Self::Welcome(WelcomeTerms {
                    version: fields.u8(TAG_1)?,
                    max_frame_bytes: fields.u32(TAG_2)?,
                    idle_timeout_seconds: fields.u32(TAG_3)?,
                })
            }
            Operation::Ping => Self::Ping {
                nonce: Fields::parse(payload, &ONE)?.u64(TAG_1)?,
            },
            Operation::Pong => Self::Pong {
                nonce: Fields::parse(payload, &ONE)?.u64(TAG_1)?,
            },
            Operation::Revoke => {
                let fields = Fields::parse(payload, &TWO)?;
                Self::Revoke(Revoke {
                    reason: fields.code(TAG_1, revocation_reason_from_code)?,
                    authorization_epoch: AuthorizationEpoch::new(fields.u64(TAG_2)?),
                })
            }
            Operation::Shutdown => Self::Shutdown(Shutdown {
                grace_seconds: Fields::parse(payload, &ONE)?.u32(TAG_1)?,
            }),
            Operation::InitReport => {
                let fields = Fields::parse(payload, &INIT_REPORT)?;
                Self::InitReport(InitReport {
                    stage: fields.code(TAG_1, InitStage::from_code)?,
                    outcome: fields.code(TAG_2, ProbeOutcome::from_code)?,
                    detail: fields.text(TAG_3, MAX_TEXT_BYTES)?,
                    claimed_vm: fields.optional_digest(TAG_4)?,
                })
            }
            Operation::ProbeResult => {
                let fields = Fields::parse(payload, &THREE)?;
                Self::ProbeResult(ProbeResult {
                    probe: fields.name(TAG_1)?,
                    outcome: fields.code(TAG_2, ProbeOutcome::from_code)?,
                    detail: fields.text(TAG_3, MAX_TEXT_BYTES)?,
                })
            }
            Operation::AllProbesPassed => Self::AllProbesPassed(AllProbesPassed {
                probe_count: Fields::parse(payload, &ONE)?.u32(TAG_1)?,
            }),
            Operation::Close => Self::Close {
                reason: Fields::parse(payload, &ONE)?.code(TAG_1, CloseReason::from_code)?,
            },
            Operation::WindowUpdate => Self::WindowUpdate {
                channel,
                credit_bytes: Fields::parse(payload, &ONE)?.u32(TAG_1)?,
            },
            Operation::StreamWindowUpdate => Self::StreamWindowUpdate {
                channel,
                stream: required()?,
                credit_bytes: Fields::parse(payload, &ONE)?.u32(TAG_1)?,
            },
            Operation::Open => {
                let open = match channel {
                    Channel::Terminal => {
                        let fields = Fields::parse(payload, &TERMINAL)?;
                        let columns = fields.u16(TAG_1)?;
                        let rows = fields.u16(TAG_2)?;
                        match fields.optional_u8(TAG_3)? {
                            None => StreamOpen::Terminal { columns, rows },
                            Some(1) if columns == 0 && rows == 0 => StreamOpen::ImageEntrypoint,
                            Some(value) => {
                                return Err(FieldRefusal::InvalidValue {
                                    tag: TAG_3,
                                    value: value as u64,
                                }
                                .into())
                            }
                        }
                    }
                    Channel::File => {
                        let fields = Fields::parse(payload, &THREE)?;
                        StreamOpen::File {
                            grant: GrantHandle(fields.u64(TAG_1)?),
                            entry: fields.name(TAG_2)?,
                            mode: fields.code(TAG_3, FileMode::from_code)?,
                        }
                    }
                    Channel::Ingress => StreamOpen::Ingress {
                        listener: Fields::parse(payload, &ONE)?.name(TAG_1)?,
                    },
                    Channel::Egress | Channel::Control => StreamOpen::Egress {
                        destination: Fields::parse(payload, &ONE)?.name(TAG_1)?,
                    },
                };
                Self::Open {
                    stream: required()?,
                    open,
                }
            }
            Operation::Opened => {
                Fields::parse(payload, &NO_FIELDS)?;
                Self::Opened {
                    channel,
                    stream: required()?,
                }
            }
            Operation::OpenRefused => Self::OpenRefused {
                channel,
                stream: required()?,
                cause: Fields::parse(payload, &ONE)?.code(TAG_1, OpenRefusalCause::from_code)?,
            },
            Operation::Data => Self::Data {
                channel,
                stream: required()?,
                bytes: Fields::parse(payload, &ONE)?
                    .bytes(TAG_1, max_data_bytes)?
                    .to_vec(),
            },
            Operation::EndOfStream => {
                Fields::parse(payload, &NO_FIELDS)?;
                Self::EndOfStream {
                    channel,
                    stream: required()?,
                }
            }
            Operation::Cancel => Self::Cancel {
                channel,
                stream: required()?,
                cause: Fields::parse(payload, &ONE)?.code(TAG_1, CancelCause::from_code)?,
            },
            Operation::Resize => {
                let fields = Fields::parse(payload, &TWO)?;
                Self::Resize {
                    stream: required()?,
                    columns: fields.u16(TAG_1)?,
                    rows: fields.u16(TAG_2)?,
                }
            }
            Operation::Exit => Self::Exit {
                stream: required()?,
                code: Fields::parse(payload, &ONE)?.i32(TAG_1)?,
            },
        };
        Ok(message)
    }
}

/// What the host may send. Welcome and window updates are issued by the link itself;
/// guest-only operations have no variant here, so the type is the direction table for
/// the host side.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "message", rename_all = "snake_case")]
pub enum HostMessage {
    OpenImageEntrypoint {
        stream: StreamId,
    },
    Ping {
        nonce: u64,
    },
    Pong {
        nonce: u64,
    },
    Revoke(Revoke),
    Shutdown(Shutdown),
    Close {
        reason: CloseReason,
    },
    OpenTerminal {
        stream: StreamId,
        columns: u16,
        rows: u16,
    },
    OpenFile {
        stream: StreamId,
        grant: GrantHandle,
        entry: LinkName,
        mode: FileMode,
    },
    OpenIngress {
        stream: StreamId,
        listener: LinkName,
    },
    Opened {
        channel: Channel,
        stream: StreamId,
    },
    OpenRefused {
        channel: Channel,
        stream: StreamId,
        cause: OpenRefusalCause,
    },
    Data {
        channel: Channel,
        stream: StreamId,
        bytes: Vec<u8>,
    },
    EndOfStream {
        channel: Channel,
        stream: StreamId,
    },
    Cancel {
        channel: Channel,
        stream: StreamId,
        cause: CancelCause,
    },
    Resize {
        stream: StreamId,
        columns: u16,
        rows: u16,
    },
}

impl From<HostMessage> for LinkMessage {
    fn from(message: HostMessage) -> Self {
        match message {
            HostMessage::OpenImageEntrypoint { stream } => Self::Open {
                stream,
                open: StreamOpen::ImageEntrypoint,
            },
            HostMessage::Ping { nonce } => Self::Ping { nonce },
            HostMessage::Pong { nonce } => Self::Pong { nonce },
            HostMessage::Revoke(revoke) => Self::Revoke(revoke),
            HostMessage::Shutdown(shutdown) => Self::Shutdown(shutdown),
            HostMessage::Close { reason } => Self::Close { reason },
            HostMessage::OpenTerminal {
                stream,
                columns,
                rows,
            } => Self::Open {
                stream,
                open: StreamOpen::Terminal { columns, rows },
            },
            HostMessage::OpenFile {
                stream,
                grant,
                entry,
                mode,
            } => Self::Open {
                stream,
                open: StreamOpen::File { grant, entry, mode },
            },
            HostMessage::OpenIngress { stream, listener } => Self::Open {
                stream,
                open: StreamOpen::Ingress { listener },
            },
            HostMessage::Opened { channel, stream } => Self::Opened { channel, stream },
            HostMessage::OpenRefused {
                channel,
                stream,
                cause,
            } => Self::OpenRefused {
                channel,
                stream,
                cause,
            },
            HostMessage::Data {
                channel,
                stream,
                bytes,
            } => Self::Data {
                channel,
                stream,
                bytes,
            },
            HostMessage::EndOfStream { channel, stream } => Self::EndOfStream { channel, stream },
            HostMessage::Cancel {
                channel,
                stream,
                cause,
            } => Self::Cancel {
                channel,
                stream,
                cause,
            },
            HostMessage::Resize {
                stream,
                columns,
                rows,
            } => Self::Resize {
                stream,
                columns,
                rows,
            },
        }
    }
}

/// The closed set of typed requests a guest frame can become. A later broker authorizes
/// each against the sandbox contract; nothing here is a host action, a path, an
/// executable or an endpoint (§2.6; §3.1 relay row).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "request", rename_all = "snake_case")]
pub enum GuestRequest {
    Ping {
        nonce: u64,
    },
    Pong {
        nonce: u64,
    },
    Close {
        reason: CloseReason,
    },
    WindowUpdate {
        channel: Channel,
        credit_bytes: u32,
    },
    /// Credit for one of the host's ingress or egress streams.
    StreamWindowUpdate {
        channel: Channel,
        stream: StreamId,
        credit_bytes: u32,
    },
    OpenFile {
        stream: StreamId,
        grant: GrantHandle,
        entry: LinkName,
        mode: FileMode,
    },
    OpenEgress {
        stream: StreamId,
        destination: LinkName,
    },
    Opened {
        channel: Channel,
        stream: StreamId,
    },
    OpenRefused {
        channel: Channel,
        stream: StreamId,
        cause: OpenRefusalCause,
    },
    Data {
        channel: Channel,
        stream: StreamId,
        bytes: Vec<u8>,
    },
    EndOfStream {
        channel: Channel,
        stream: StreamId,
    },
    Cancel {
        channel: Channel,
        stream: StreamId,
        cause: CancelCause,
    },
}

/// What a guest reported: its hello, init stages, probes, the "all probes passed"
/// statement and terminal exits. Every one is the guest's word.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "report", rename_all = "snake_case")]
pub enum ReportBody {
    Hello(Hello),
    Init(InitReport),
    Probe(ProbeResult),
    AllProbesPassed(AllProbesPassed),
    TerminalExit { stream: StreamId, code: i32 },
}

/// A guest message sorted into what the host does with it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Classified {
    Request(GuestRequest),
    Report(ReportBody),
    /// A message only the host sends; the direction table refuses it before this point.
    HostOnly,
}

impl Classified {
    pub fn of(message: LinkMessage) -> Self {
        match message {
            LinkMessage::Hello(hello) => Self::Report(ReportBody::Hello(hello)),
            LinkMessage::InitReport(report) => Self::Report(ReportBody::Init(report)),
            LinkMessage::ProbeResult(result) => Self::Report(ReportBody::Probe(result)),
            LinkMessage::AllProbesPassed(passed) => {
                Self::Report(ReportBody::AllProbesPassed(passed))
            }
            LinkMessage::Exit { stream, code } => {
                Self::Report(ReportBody::TerminalExit { stream, code })
            }
            LinkMessage::Ping { nonce } => Self::Request(GuestRequest::Ping { nonce }),
            LinkMessage::Pong { nonce } => Self::Request(GuestRequest::Pong { nonce }),
            LinkMessage::Close { reason } => Self::Request(GuestRequest::Close { reason }),
            LinkMessage::WindowUpdate {
                channel,
                credit_bytes,
            } => Self::Request(GuestRequest::WindowUpdate {
                channel,
                credit_bytes,
            }),
            LinkMessage::StreamWindowUpdate {
                channel,
                stream,
                credit_bytes,
            } => Self::Request(GuestRequest::StreamWindowUpdate {
                channel,
                stream,
                credit_bytes,
            }),
            LinkMessage::Open { stream, open } => match open {
                StreamOpen::File { grant, entry, mode } => Self::Request(GuestRequest::OpenFile {
                    stream,
                    grant,
                    entry,
                    mode,
                }),
                StreamOpen::Egress { destination } => Self::Request(GuestRequest::OpenEgress {
                    stream,
                    destination,
                }),
                StreamOpen::Terminal { .. }
                | StreamOpen::ImageEntrypoint
                | StreamOpen::Ingress { .. } => Self::HostOnly,
            },
            LinkMessage::Opened { channel, stream } => {
                Self::Request(GuestRequest::Opened { channel, stream })
            }
            LinkMessage::OpenRefused {
                channel,
                stream,
                cause,
            } => Self::Request(GuestRequest::OpenRefused {
                channel,
                stream,
                cause,
            }),
            LinkMessage::Data {
                channel,
                stream,
                bytes,
            } => Self::Request(GuestRequest::Data {
                channel,
                stream,
                bytes,
            }),
            LinkMessage::EndOfStream { channel, stream } => {
                Self::Request(GuestRequest::EndOfStream { channel, stream })
            }
            LinkMessage::Cancel {
                channel,
                stream,
                cause,
            } => Self::Request(GuestRequest::Cancel {
                channel,
                stream,
                cause,
            }),
            LinkMessage::Challenge { .. }
            | LinkMessage::Welcome(_)
            | LinkMessage::Revoke(_)
            | LinkMessage::Shutdown(_)
            | LinkMessage::Resize { .. } => Self::HostOnly,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::foundation::ids::digest;

    fn samples() -> Vec<LinkMessage> {
        let stream = StreamId::new(3).unwrap();
        let name = LinkName::new("dest-1").unwrap();
        vec![
            LinkMessage::Open {
                stream,
                open: StreamOpen::ImageEntrypoint,
            },
            LinkMessage::Challenge {
                connection: Connection::from_bytes(*b"connection-nonce"),
            },
            LinkMessage::Hello(Hello {
                guest_version: 1,
                agent_build: digest("yougori/test/build/v1", &[b"agent"]),
                claimed_vm: Some(digest("yougori/test/vm/v1", &[b"vm"])),
                claimed_boot: Some(4),
            }),
            LinkMessage::Hello(Hello {
                guest_version: 1,
                agent_build: digest("yougori/test/build/v1", &[b"agent"]),
                claimed_vm: None,
                claimed_boot: None,
            }),
            LinkMessage::Welcome(WelcomeTerms {
                version: 1,
                max_frame_bytes: 65_536,
                idle_timeout_seconds: 60,
            }),
            LinkMessage::Ping { nonce: 5 },
            LinkMessage::Pong { nonce: u64::MAX },
            LinkMessage::Revoke(Revoke {
                reason: RevocationReason::SecurityEvent,
                authorization_epoch: AuthorizationEpoch::new(9),
            }),
            LinkMessage::Shutdown(Shutdown { grace_seconds: 30 }),
            LinkMessage::InitReport(InitReport {
                stage: InitStage::Channel,
                outcome: ProbeOutcome::Passed,
                detail: "vsock up".to_owned(),
                claimed_vm: None,
            }),
            LinkMessage::ProbeResult(ProbeResult {
                probe: LinkName::new("seccomp-profile").unwrap(),
                outcome: ProbeOutcome::Failed,
                detail: String::new(),
            }),
            LinkMessage::AllProbesPassed(AllProbesPassed { probe_count: 12 }),
            LinkMessage::Close {
                reason: CloseReason::Orderly,
            },
            LinkMessage::WindowUpdate {
                channel: Channel::File,
                credit_bytes: 4096,
            },
            LinkMessage::StreamWindowUpdate {
                channel: Channel::Egress,
                stream,
                credit_bytes: 4096,
            },
            LinkMessage::Open {
                stream,
                open: StreamOpen::Terminal {
                    columns: 80,
                    rows: 24,
                },
            },
            LinkMessage::Open {
                stream,
                open: StreamOpen::File {
                    grant: GrantHandle(77),
                    entry: LinkName::new("notes.txt").unwrap(),
                    mode: FileMode::Read,
                },
            },
            LinkMessage::Open {
                stream,
                open: StreamOpen::Ingress {
                    listener: name.clone(),
                },
            },
            LinkMessage::Open {
                stream,
                open: StreamOpen::Egress { destination: name },
            },
            LinkMessage::Opened {
                channel: Channel::File,
                stream,
            },
            LinkMessage::OpenRefused {
                channel: Channel::Egress,
                stream,
                cause: OpenRefusalCause::NotAuthorized,
            },
            LinkMessage::Data {
                channel: Channel::Ingress,
                stream,
                bytes: vec![0, 1, 2, 255],
            },
            LinkMessage::EndOfStream {
                channel: Channel::Terminal,
                stream,
            },
            LinkMessage::Cancel {
                channel: Channel::File,
                stream,
                cause: CancelCause::TimedOut,
            },
            LinkMessage::Resize {
                stream,
                columns: 132,
                rows: 43,
            },
            LinkMessage::Exit { stream, code: -1 },
        ]
    }

    #[test]
    fn every_message_round_trips_through_its_payload() {
        for message in samples() {
            let payload = message.encode_payload().unwrap();
            let decoded = LinkMessage::decode(
                message.channel(),
                message.operation(),
                message.stream_code(),
                &payload,
                1024,
            )
            .unwrap();
            assert_eq!(decoded, message);
        }
    }

    #[test]
    fn stream_ids_are_checked_against_the_operation() {
        let payload = LinkMessage::Ping { nonce: 1 }.encode_payload().unwrap();
        assert_eq!(
            LinkMessage::decode(Channel::Control, Operation::Ping, 1, &payload, 16),
            Err(PayloadRefusal::StreamIdForbidden { stream: 1 })
        );
        assert_eq!(
            LinkMessage::decode(Channel::Egress, Operation::EndOfStream, 0, &[], 16),
            Err(PayloadRefusal::StreamIdRequired)
        );
        assert_eq!(StreamId::new(0), None);
        assert_eq!(StreamId::new(1).unwrap().opener(), Sender::Guest);
        assert_eq!(StreamId::new(2).unwrap().opener(), Sender::Host);
    }

    #[test]
    fn codes_round_trip_and_unknown_codes_are_refused() {
        for code in 0..=255u8 {
            if let Some(reason) = revocation_reason_from_code(code) {
                assert_eq!(revocation_reason_code(reason), code);
            }
            if let Some(stage) = InitStage::from_code(code) {
                assert_eq!(stage.code(), code);
            }
        }
        for reason in [
            RevocationReason::UserRequested,
            RevocationReason::PolicyChanged,
            RevocationReason::AuthorizationExpired,
            RevocationReason::SecurityEvent,
            RevocationReason::OwnerReclaimed,
        ] {
            assert_eq!(
                revocation_reason_from_code(revocation_reason_code(reason)),
                Some(reason)
            );
        }
        let bad = FieldWriter::new()
            .u8(1, 9)
            .u8(2, 1)
            .text(3, "")
            .unwrap()
            .finish();
        assert_eq!(
            LinkMessage::decode(Channel::Control, Operation::InitReport, 0, &bad, 16),
            Err(PayloadRefusal::Field(FieldRefusal::InvalidValue {
                tag: 1,
                value: 9
            }))
        );
    }

    #[test]
    fn a_challenge_carries_exactly_one_connection_field() {
        for length in [0usize, 15, 17] {
            let payload = FieldWriter::new()
                .bytes(1, &vec![7; length])
                .unwrap()
                .finish();
            let refused =
                LinkMessage::decode(Channel::Control, Operation::Challenge, 0, &payload, 16)
                    .unwrap_err();
            let expected = if length > CONNECTION_NONCE_BYTES {
                FieldRefusal::TooLong {
                    tag: 1,
                    max_bytes: CONNECTION_NONCE_BYTES,
                    found_bytes: length,
                }
            } else {
                FieldRefusal::WrongLength {
                    tag: 1,
                    expected_bytes: CONNECTION_NONCE_BYTES,
                    found_bytes: length,
                }
            };
            assert_eq!(refused, PayloadRefusal::Field(expected), "{length}");
        }
    }

    #[test]
    fn data_is_bounded_by_the_caller() {
        let payload = LinkMessage::Data {
            channel: Channel::File,
            stream: StreamId::new(1).unwrap(),
            bytes: vec![0; 10],
        }
        .encode_payload()
        .unwrap();
        assert_eq!(
            LinkMessage::decode(Channel::File, Operation::Data, 1, &payload, 9),
            Err(PayloadRefusal::Field(FieldRefusal::TooLong {
                tag: 1,
                max_bytes: 9,
                found_bytes: 10
            }))
        );
    }

    #[test]
    fn names_on_the_link_are_never_paths_or_urls() {
        for text in [
            "../secret",
            "/etc/passwd",
            "C:\\Windows",
            "http://host:1/",
            "a b",
        ] {
            let payload = FieldWriter::new().text(1, text).unwrap().finish();
            assert!(matches!(
                LinkMessage::decode(Channel::Egress, Operation::Open, 1, &payload, 16),
                Err(PayloadRefusal::Field(FieldRefusal::NotName { tag: 1, .. }))
            ));
            let file = FieldWriter::new()
                .u64(1, 1)
                .text(2, text)
                .unwrap()
                .u8(3, 1)
                .finish();
            assert!(matches!(
                LinkMessage::decode(Channel::File, Operation::Open, 1, &file, 16),
                Err(PayloadRefusal::Field(FieldRefusal::NotName { tag: 2, .. }))
            ));
        }
    }

    #[test]
    fn host_only_messages_never_classify_as_requests() {
        for message in samples() {
            let host_only = match &message {
                LinkMessage::Challenge { .. }
                | LinkMessage::Welcome(_)
                | LinkMessage::Revoke(_)
                | LinkMessage::Shutdown(_)
                | LinkMessage::Resize { .. } => true,
                LinkMessage::Open { open, .. } => matches!(
                    open,
                    StreamOpen::Terminal { .. }
                        | StreamOpen::ImageEntrypoint
                        | StreamOpen::Ingress { .. }
                ),
                _ => false,
            };
            match Classified::of(message.clone()) {
                Classified::HostOnly => assert!(host_only, "{message:?}"),
                _ => assert!(!host_only, "{message:?}"),
            }
        }
    }
}
