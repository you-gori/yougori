//! The conformance corpus: valid and hostile guest frames as a fixture inside this module,
//! the mutations of VM-CP-25 (oversized, truncated, slow, recursive, duplicate-field and
//! cancelled frames) and a replay harness (VM-W50 line 2675 "parsers survive bounded fuzz
//! corpus"; §16.1 line 3048 "one shared conformance corpus"). The Go guest side replays
//! the same file: its encoder must produce the valid frames byte for byte, and the hostile
//! cases document what the host refuses.
//!
//! # Corpus format (`yougori-link-corpus/v2`)
//!
//! One JSON object:
//!
//! - `format`: the string `yougori-link-corpus/v2` (v1 had no connection and frames of
//!   protocol version 1).
//! - `protocol_version`: the frame version the cases use.
//! - `secret_hex`, `vm_hex`, `boot_generation`: the test instance every case is bound to.
//!   The secret is test material only; keys and tags derive from it as [`LinkBinding`]
//!   does, and the VM is the digest of its CORE-04 handle.
//! - `connection_hex`: the connection nonce every case's link is challenged with (test
//!   material too; a real host draws a fresh one per connection).
//! - `challenge_hex`: the host's challenge frame for that nonce, byte for byte: the first
//!   frame every case's link writes (host-to-guest sequence 1), so the guest side can
//!   check its reading of a host frame. Every replay checks the link wrote exactly it.
//! - `cases`: a list; each case runs against a fresh challenged host link
//!   ([`HostLink::connect`]) with the default limits and a clock at zero, and has
//!   `name`, `kind` (`valid` or `hostile`), `notes`, `steps` and `expect`. The link's
//!   challenge is not listed as a step.
//! - A step is `{"kind": "guest", "frame_hex": ...}`, a whole frame the guest sends, or
//!   `{"kind": "host", "action": {...}}`, a message the host sends first (an answer to a
//!   guest open, or a host-opened stream). Guest frames carry the connection and
//!   consecutive sequences from 1 in step order. A `kind` or `action` that is not a
//!   string, and a key that appears twice in one object, are refused.
//! - `expect`: `outcome` is `accepted` (the last guest frame produced no refusal) or
//!   `refused` with `reason`, the stable refusal code; `link` is `open` or `closed`, the
//!   link's phase after the case. Every guest frame before the last must be accepted.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::foundation::coordination::VmInstanceId;
use crate::foundation::ids::{Digest, ManualClock, MonotonicTime, SandboxBootGeneration};

use super::connection::{ConnectionNonce, NonceRefusal};
use super::fields::{FieldWriter, LinkName, FIELD_OVERHEAD_BYTES};
use super::limits::{LimitsError, LinkLimits};
use super::link::{encode_frame_on, seal, HostLink, LinkEvent, SendRefusal};
use super::messages::{
    CancelCause, CloseReason, FileMode, GrantHandle, HostMessage, LinkMessage, OpenRefusalCause,
    StreamId,
};
use super::secret::{BootstrapSecret, LinkBinding, SecretRefusal};
use super::wire::{Channel, FrameHeader, Operation, Sender, HEADER_BYTES, TAG_BYTES};

/// The format tag of the corpus file.
pub const CORPUS_FORMAT: &str = "yougori-link-corpus/v2";

/// The corpus fixture shipped with the module.
pub const CORPUS_JSON: &str = include_str!("corpus.json");

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Corpus {
    pub format: String,
    pub protocol_version: u8,
    pub secret_hex: String,
    pub vm_hex: String,
    pub boot_generation: u64,
    pub connection_hex: String,
    pub challenge_hex: String,
    pub cases: Vec<CorpusCase>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaseKind {
    Valid,
    Hostile,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CorpusCase {
    pub name: String,
    pub kind: CaseKind,
    pub notes: String,
    pub steps: Vec<Step>,
    pub expect: Expectation,
}

/// One step of a case. It reads through `foundation::strict_serde`: a `kind` or a nested
/// `action` that is not a string, or a key repeated in one object, is refused.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
#[serde(remote = "Self")]
pub enum Step {
    Guest { frame_hex: String },
    Host { action: HostAction },
}

crate::foundation::strict_serde::strict_tag!(Step, "kind");

/// A host message a case sends between guest frames. Names and modes are typed as on
/// the link. It reads through `foundation::strict_serde`, as [`Step`] does.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
#[serde(remote = "Self")]
pub enum HostAction {
    Opened {
        channel: Channel,
        stream: u32,
    },
    OpenRefused {
        channel: Channel,
        stream: u32,
        cause: OpenRefusalCause,
    },
    OpenTerminal {
        stream: u32,
        columns: u16,
        rows: u16,
    },
    OpenIngress {
        stream: u32,
        listener: LinkName,
    },
    OpenFile {
        stream: u32,
        grant: u64,
        entry: LinkName,
        mode: FileMode,
    },
    Cancel {
        channel: Channel,
        stream: u32,
        cause: CancelCause,
    },
    EndOfStream {
        channel: Channel,
        stream: u32,
    },
    Close {
        reason: CloseReason,
    },
}

crate::foundation::strict_serde::strict_tag!(HostAction, "action");

impl HostAction {
    fn message(&self) -> Result<HostMessage, CorpusError> {
        let stream = |id: u32| StreamId::new(id).ok_or(CorpusError::ZeroStream);
        Ok(match self {
            Self::Opened {
                channel,
                stream: id,
            } => HostMessage::Opened {
                channel: *channel,
                stream: stream(*id)?,
            },
            Self::OpenRefused {
                channel,
                stream: id,
                cause,
            } => HostMessage::OpenRefused {
                channel: *channel,
                stream: stream(*id)?,
                cause: *cause,
            },
            Self::OpenTerminal {
                stream: id,
                columns,
                rows,
            } => HostMessage::OpenTerminal {
                stream: stream(*id)?,
                columns: *columns,
                rows: *rows,
            },
            Self::OpenIngress {
                stream: id,
                listener,
            } => HostMessage::OpenIngress {
                stream: stream(*id)?,
                listener: listener.clone(),
            },
            Self::OpenFile {
                stream: id,
                grant,
                entry,
                mode,
            } => HostMessage::OpenFile {
                stream: stream(*id)?,
                grant: GrantHandle(*grant),
                entry: entry.clone(),
                mode: *mode,
            },
            Self::Cancel {
                channel,
                stream: id,
                cause,
            } => HostMessage::Cancel {
                channel: *channel,
                stream: stream(*id)?,
                cause: *cause,
            },
            Self::EndOfStream {
                channel,
                stream: id,
            } => HostMessage::EndOfStream {
                channel: *channel,
                stream: stream(*id)?,
            },
            Self::Close { reason } => HostMessage::Close { reason: *reason },
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Accepted,
    Refused,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LinkExpectation {
    Open,
    Closed,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Expectation {
    pub outcome: Outcome,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    pub link: LinkExpectation,
}

/// Why the corpus or a case could not be used.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CorpusError {
    Json(String),
    WrongFormat {
        found: String,
    },
    BadHex {
        field: &'static str,
    },
    Secret(SecretRefusal),
    Nonce(NonceRefusal),
    Limits(LimitsError),
    ZeroStream,
    /// A host step the link refused: the case is inconsistent.
    HostStepRefused {
        step: usize,
        refusal: SendRefusal,
    },
    /// A guest frame before the last was refused: the case is inconsistent.
    SetupRefused {
        step: usize,
        code: String,
    },
    NoGuestFrames,
    /// The link's first frame is not the corpus's `challenge_hex`.
    ChallengeMismatch,
}

impl fmt::Display for CorpusError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Json(detail) => write!(f, "the corpus is not valid JSON: {detail}"),
            Self::WrongFormat { found } => {
                write!(f, "corpus format {found:?} is not {CORPUS_FORMAT}")
            }
            Self::BadHex { field } => write!(f, "{field} is not hexadecimal"),
            Self::Secret(refusal) => write!(f, "the corpus secret was refused: {refusal}"),
            Self::Nonce(refusal) => write!(f, "the corpus connection was refused: {refusal}"),
            Self::Limits(error) => write!(f, "the limits were refused: {error}"),
            Self::ZeroStream => f.write_str("a host step names stream 0"),
            Self::HostStepRefused { step, refusal } => {
                write!(f, "host step {step} was refused: {refusal}")
            }
            Self::SetupRefused { step, code } => {
                write!(f, "guest frame {step} was refused before the last: {code}")
            }
            Self::NoGuestFrames => f.write_str("the case has no guest frame"),
            Self::ChallengeMismatch => {
                f.write_str("the link's first frame is not the corpus's challenge")
            }
        }
    }
}

impl std::error::Error for CorpusError {}

impl Corpus {
    /// Parses the shipped fixture.
    pub fn shipped() -> Result<Self, CorpusError> {
        Self::parse(CORPUS_JSON)
    }

    pub fn parse(json: &str) -> Result<Self, CorpusError> {
        let corpus: Self =
            serde_json::from_str(json).map_err(|error| CorpusError::Json(error.to_string()))?;
        if corpus.format != CORPUS_FORMAT {
            return Err(CorpusError::WrongFormat {
                found: corpus.format,
            });
        }
        Ok(corpus)
    }

    /// The binding every case runs under.
    pub fn binding(&self) -> Result<LinkBinding, CorpusError> {
        let secret = hex::decode(&self.secret_hex).map_err(|_| CorpusError::BadHex {
            field: "secret_hex",
        })?;
        let secret = BootstrapSecret::new(&secret).map_err(CorpusError::Secret)?;
        let vm =
            Digest::from_hex(&self.vm_hex).map_err(|_| CorpusError::BadHex { field: "vm_hex" })?;
        Ok(LinkBinding::new(
            VmInstanceId::new(vm),
            SandboxBootGeneration::new(self.boot_generation),
            secret,
        ))
    }

    /// The connection nonce every case's link is challenged with.
    pub fn connection(&self) -> Result<ConnectionNonce, CorpusError> {
        let material = hex::decode(&self.connection_hex).map_err(|_| CorpusError::BadHex {
            field: "connection_hex",
        })?;
        ConnectionNonce::new(&material).map_err(CorpusError::Nonce)
    }

    /// A fresh challenged host link for one case.
    pub fn link(&self, limits: LinkLimits) -> Result<HostLink<ManualClock>, CorpusError> {
        let binding = self.binding()?;
        let nonce = self.connection()?;
        HostLink::connect(
            binding,
            nonce,
            limits,
            ManualClock::new(MonotonicTime::ZERO),
        )
        .map_err(CorpusError::Limits)
    }
}

/// What the last guest frame of a replay did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LastOutcome {
    Accepted,
    Refused { code: String },
}

/// The result of replaying one case.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReplayOutcome {
    pub last: LastOutcome,
    pub link_open: bool,
    /// The most bytes the decoder held at any time.
    pub peak_decoder_bytes: usize,
    /// The most bytes buffered on any channel at any time.
    pub peak_buffered_bytes: u64,
}

impl ReplayOutcome {
    /// Whether the outcome is what the case expects.
    pub fn matches(&self, expect: &Expectation) -> bool {
        let outcome_ok = match (&self.last, expect.outcome) {
            (LastOutcome::Accepted, Outcome::Accepted) => true,
            (LastOutcome::Refused { code }, Outcome::Refused) => {
                expect.reason.as_deref() == Some(code.as_str())
            }
            _ => false,
        };
        let link_ok = match expect.link {
            LinkExpectation::Open => self.link_open,
            LinkExpectation::Closed => !self.link_open,
        };
        outcome_ok && link_ok
    }
}

/// How the bytes of the last guest frame reach the link.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Feed {
    Whole,
    OneByteAtATime,
    /// The last frame whole, then the peer disconnects.
    WholeThenDisconnect,
}

/// Drives one case. `last_frames` replaces the last guest frame with the given frames
/// (a mutation); `None` replays the case as written.
pub fn replay(
    corpus: &Corpus,
    case: &CorpusCase,
    limits: LinkLimits,
    last_frames: Option<&[Vec<u8>]>,
    feed: Feed,
) -> Result<ReplayOutcome, CorpusError> {
    let mut link = corpus.link(limits)?;
    let challenge = hex::decode(&corpus.challenge_hex).map_err(|_| CorpusError::BadHex {
        field: "challenge_hex",
    })?;
    if link.next_outbound() != Some(challenge) {
        return Err(CorpusError::ChallengeMismatch);
    }
    let last_guest_step = case
        .steps
        .iter()
        .rposition(|step| matches!(step, Step::Guest { .. }))
        .ok_or(CorpusError::NoGuestFrames)?;
    let mut peak_decoder_bytes = 0usize;
    let mut peak_buffered_bytes = 0u64;
    let mut last = LastOutcome::Accepted;
    let record_peaks =
        |link: &HostLink<ManualClock>, peak_decoder: &mut usize, peak_buffered: &mut u64| {
            *peak_decoder = (*peak_decoder).max(link.decoder_buffered_bytes());
            for channel in Channel::ALL {
                *peak_buffered = (*peak_buffered).max(link.channel(channel).buffered_bytes);
            }
        };
    for (index, step) in case.steps.iter().enumerate() {
        match step {
            Step::Host { action } => {
                let message = action.message()?;
                link.send(message)
                    .map_err(|refusal| CorpusError::HostStepRefused {
                        step: index,
                        refusal,
                    })?;
                while link.next_outbound().is_some() {}
            }
            Step::Guest { frame_hex } => {
                let frame = hex::decode(frame_hex)
                    .map_err(|_| CorpusError::BadHex { field: "frame_hex" })?;
                let is_last = index == last_guest_step;
                let frames: Vec<Vec<u8>> = match (is_last, last_frames) {
                    (true, Some(replacement)) => replacement.to_vec(),
                    _ => vec![frame],
                };
                let mut events = Vec::new();
                for frame in &frames {
                    match (is_last, feed) {
                        (true, Feed::OneByteAtATime) => {
                            for byte in frame {
                                events.extend(link.receive(std::slice::from_ref(byte)));
                                record_peaks(
                                    &link,
                                    &mut peak_decoder_bytes,
                                    &mut peak_buffered_bytes,
                                );
                            }
                        }
                        _ => {
                            events.extend(link.receive(frame));
                            record_peaks(&link, &mut peak_decoder_bytes, &mut peak_buffered_bytes);
                        }
                    }
                }
                if is_last && feed == Feed::WholeThenDisconnect {
                    events.extend(link.peer_closed());
                }
                let refused = events.iter().find_map(|event| match event {
                    LinkEvent::Refused(refusal) => Some(refusal.reason.code().to_owned()),
                    _ => None,
                });
                match (is_last, refused) {
                    (false, Some(code)) => {
                        return Err(CorpusError::SetupRefused { step: index, code })
                    }
                    (false, None) => {}
                    (true, Some(code)) => last = LastOutcome::Refused { code },
                    (true, None) => last = LastOutcome::Accepted,
                }
            }
        }
    }
    Ok(ReplayOutcome {
        last,
        link_open: !link.is_closed(),
        peak_decoder_bytes,
        peak_buffered_bytes,
    })
}

/// The VM-CP-25 mutations applied to every valid frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mutation {
    /// The header announces a frame above the limit.
    Oversized,
    /// The frame stops short and the peer goes away.
    Truncated,
    /// The frame arrives one byte at a time.
    Slow,
    /// The payload is wrapped in itself as deep as the message limit allows.
    Recursive,
    /// A field of the payload appears twice.
    DuplicateField,
    /// The stream (or the link) is cancelled before the frame arrives.
    Cancelled,
}

impl Mutation {
    pub const ALL: [Self; 6] = [
        Self::Oversized,
        Self::Truncated,
        Self::Slow,
        Self::Recursive,
        Self::DuplicateField,
        Self::Cancelled,
    ];
}

/// A sealed frame taken apart.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FrameParts {
    pub header: FrameHeader,
    pub payload: Vec<u8>,
    pub tag: [u8; TAG_BYTES],
}

/// Splits a sealed frame; `None` when it is too short or its header does not decode.
pub fn split_frame(frame: &[u8]) -> Option<FrameParts> {
    let head = <[u8; HEADER_BYTES]>::try_from(frame.get(..HEADER_BYTES)?).ok()?;
    let header = FrameHeader::decode(&head, u32::MAX).ok()?;
    let payload_end = HEADER_BYTES + header.payload_bytes as usize;
    let payload = frame.get(HEADER_BYTES..payload_end)?.to_vec();
    let tag = <[u8; TAG_BYTES]>::try_from(frame.get(payload_end..payload_end + TAG_BYTES)?).ok()?;
    Some(FrameParts {
        header,
        payload,
        tag,
    })
}

/// Seals `parts` again as the guest, with a new sequence and payload.
pub fn reseal(binding: &LinkBinding, parts: &FrameParts, sequence: u64, payload: &[u8]) -> Vec<u8> {
    let header = FrameHeader {
        sequence,
        payload_bytes: u32::try_from(payload.len()).unwrap_or(u32::MAX),
        ..parts.header
    };
    seal(binding, Sender::Guest, &header, payload)
}

/// The frames that replace a valid frame under `mutation`, sealed as the guest would
/// (guest root holds the bootstrap material, so a mutated frame can be authentic).
pub fn mutate(
    binding: &LinkBinding,
    limits: &LinkLimits,
    frame: &[u8],
    mutation: Mutation,
) -> Option<Vec<Vec<u8>>> {
    let parts = split_frame(frame)?;
    let sequence = parts.header.sequence;
    Some(match mutation {
        Mutation::Oversized => {
            let mut bytes = frame.to_vec();
            if let Some(length) = bytes.get_mut(28..32) {
                length.copy_from_slice(&limits.max_frame_bytes.to_be_bytes());
            }
            vec![bytes]
        }
        Mutation::Truncated => vec![frame
            .get(..frame.len().saturating_sub(1))
            .unwrap_or(&[])
            .to_vec()],
        Mutation::Slow => vec![frame.to_vec()],
        Mutation::Recursive => {
            let max = limits.quota(parts.header.channel).max_message_bytes as usize;
            let mut payload = parts.payload.clone();
            while payload.len() + FIELD_OVERHEAD_BYTES <= max
                && payload.len() + FIELD_OVERHEAD_BYTES <= u16::MAX as usize
            {
                payload = FieldWriter::new().bytes(1, &payload).ok()?.finish();
            }
            vec![reseal(binding, &parts, sequence, &payload)]
        }
        Mutation::DuplicateField => {
            let first_len = parts.payload.get(1..3).map(|len| {
                usize::from(u16::from_be_bytes([len[0], len[1]])) + FIELD_OVERHEAD_BYTES
            });
            let mut payload = parts.payload.clone();
            match first_len.and_then(|len| parts.payload.get(..len)) {
                Some(first) => payload.extend_from_slice(first),
                None => {
                    let field = FieldWriter::new().u8(1, 1).finish();
                    payload.extend_from_slice(&field);
                    payload.extend_from_slice(&field);
                }
            }
            vec![reseal(binding, &parts, sequence, &payload)]
        }
        Mutation::Cancelled => {
            let stream = StreamId::new(parts.header.stream);
            let channel = parts.header.channel;
            let cancel = match (stream, channel.is_bulk()) {
                (Some(stream), true) => LinkMessage::Cancel {
                    channel,
                    stream,
                    cause: CancelCause::Requested,
                },
                _ => LinkMessage::Close {
                    reason: CloseReason::Orderly,
                },
            };
            let cancel_frame = encode_frame_on(
                binding,
                parts.header.connection,
                Sender::Guest,
                sequence,
                &cancel,
            )
            .ok()?;
            vec![
                cancel_frame,
                reseal(binding, &parts, sequence + 1, &parts.payload),
            ]
        }
    })
}

/// The operation a sealed frame carries, for tests that sort outcomes by it.
pub fn operation_of(frame: &[u8]) -> Option<Operation> {
    let parts = split_frame(frame)?;
    Operation::decode(parts.header.channel, parts.header.operation_code)
}
