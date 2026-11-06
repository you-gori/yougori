//! The wire format: one versioned frame header with version, channel, operation, stream,
//! sequence, generation and connection binding and length, the closed operation set with
//! its channel and directionality table, and the framing refusals (§3.2 lines 2063–2070:
//! "one versioned protocol", "typed operations and per-channel directionality",
//! "generation/connection binding", "parser rejection of unknown privileged operations";
//! VM-R59 line 2924 "versioning, limits, replay").
//!
//! Frame layout of version 3, all integers big-endian:
//!
//! | bytes | field |
//! | --- | --- |
//! | 0–3 | magic `YGLK` |
//! | 4 | protocol version, [`PROTOCOL_VERSION`] |
//! | 5 | channel code, [`Channel::code`] |
//! | 6 | operation code, [`Operation::code`] |
//! | 7 | flags, reserved and zero |
//! | 8–11 | stream id, zero for channel-level operations |
//! | 12–19 | sequence, per direction and connection, starting at 1 |
//! | 20–27 | boot generation the frame is bound to |
//! | 28–31 | payload length in bytes |
//! | 32–47 | connection the frame is bound to ([`Connection`]) |
//!
//! The payload follows the header and the HMAC-SHA256 tag over header and payload follows
//! the payload, so a frame is [`FRAME_OVERHEAD_BYTES`] plus the payload length.
//!
//! Version 1 had the same first 32 bytes and no connection field: a link was bound to
//! the boot generation only, so frames recorded on one connection of a boot were
//! accepted on the next. Its frames are refused as
//! [`FramingRefusal::RetiredVersion`].
//!
//! Version 2 had this layout and flow-controlled every bulk channel as a whole, so on the
//! ingress and egress channels one stream whose reader stopped held the channel's whole
//! window and stalled every other stream there. Version 3 flow-controls those two channels
//! per stream ([`Operation::StreamWindowUpdate`], [`Channel::has_stream_windows`]); the
//! channel-level [`Operation::WindowUpdate`] stays on the terminal and file channels. A
//! version 2 frame is refused as an unsupported version.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::foundation::transfer::HMAC_SHA256_TAG_BYTES;

use super::connection::{Connection, CONNECTION_NONCE_BYTES};

/// The first four bytes of every frame.
pub const MAGIC: [u8; 4] = *b"YGLK";
/// The only protocol version this host speaks (§3.2 "one versioned protocol").
pub const PROTOCOL_VERSION: u8 = 3;
/// The version before the connection binding; refused by name.
pub const RETIRED_PROTOCOL_VERSION: u8 = 1;
/// The fixed header length.
pub const HEADER_BYTES: usize = 32 + CONNECTION_NONCE_BYTES;
/// The authentication tag length.
pub const TAG_BYTES: usize = HMAC_SHA256_TAG_BYTES;
/// Header plus tag: what a frame costs beyond its payload.
pub const FRAME_OVERHEAD_BYTES: usize = HEADER_BYTES + TAG_BYTES;

/// The five channels of §3.2 ("independent quotas for control, terminal, file, ingress
/// and egress channels"). Control carries handshake, liveness, revocation, lifecycle and
/// guest reports; the other four carry streams.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Channel {
    Control,
    Terminal,
    File,
    Ingress,
    Egress,
}

impl Channel {
    pub const ALL: [Self; 5] = [
        Self::Control,
        Self::Terminal,
        Self::File,
        Self::Ingress,
        Self::Egress,
    ];

    /// The bulk channels, over which control has priority.
    pub const BULK: [Self; 4] = [Self::Terminal, Self::File, Self::Ingress, Self::Egress];

    pub const fn code(self) -> u8 {
        match self {
            Self::Control => 0,
            Self::Terminal => 1,
            Self::File => 2,
            Self::Ingress => 3,
            Self::Egress => 4,
        }
    }

    pub const fn from_code(code: u8) -> Option<Self> {
        match code {
            0 => Some(Self::Control),
            1 => Some(Self::Terminal),
            2 => Some(Self::File),
            3 => Some(Self::Ingress),
            4 => Some(Self::Egress),
            _ => None,
        }
    }

    /// Position in per-channel tables.
    pub const fn index(self) -> usize {
        self.code() as usize
    }

    /// Whether the channel carries streams and bulk bytes rather than control.
    pub const fn is_bulk(self) -> bool {
        !matches!(self, Self::Control)
    }

    /// Whether the channel's data is flow-controlled per stream (version 3: ingress and
    /// egress, whose streams are independent connections) rather than per channel.
    pub const fn has_stream_windows(self) -> bool {
        matches!(self, Self::Ingress | Self::Egress)
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::Control => "control",
            Self::Terminal => "terminal",
            Self::File => "file",
            Self::Ingress => "ingress",
            Self::Egress => "egress",
        }
    }
}

impl fmt::Display for Channel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// Which end of the link sent or may send a frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Sender {
    Host,
    Guest,
}

/// The directionality of one operation on one channel (§3.2 "per-channel
/// directionality").
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    HostToGuest,
    GuestToHost,
    Both,
}

impl Direction {
    pub const fn allows(self, sender: Sender) -> bool {
        match (self, sender) {
            (Self::Both, _) => true,
            (Self::HostToGuest, Sender::Host) => true,
            (Self::GuestToHost, Sender::Guest) => true,
            _ => false,
        }
    }
}

/// Whether an operation names a stream in the header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StreamUse {
    /// The stream id must be zero.
    None,
    /// The stream id must be non-zero.
    Required,
}

/// The closed operation set. Each operation is valid on some channels in some direction
/// ([`Operation::direction`]); everything else is an unknown operation and refused
/// (§3.2 "parser rejection of unknown privileged operations").
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Operation {
    /// The host's first frame on a challenged link: the connection's nonce, which the
    /// guest's hello and every later frame must carry.
    Challenge,
    /// The guest's first frame: its protocol version and agent build.
    Hello,
    /// The host's answer to a hello: the terms of the link.
    Welcome,
    Ping,
    Pong,
    /// Authority revoked; carries the reason and the new authorization epoch.
    Revoke,
    /// The host asks the guest to stop within a grace period.
    Shutdown,
    /// A guest report about one init stage (§3.3).
    InitReport,
    /// A guest report about one probe.
    ProbeResult,
    /// A guest report that every probe passed (VM-CP-25).
    AllProbesPassed,
    /// Orderly end of the link.
    Close,
    /// Receive credit granted on the terminal or file channel (backpressure).
    WindowUpdate,
    /// Receive credit granted on one ingress or egress stream (version 3).
    StreamWindowUpdate,
    /// Opens a stream; the payload depends on the channel.
    Open,
    /// The other end accepted an open.
    Opened,
    /// The other end refused an open.
    OpenRefused,
    /// Opaque bytes on an open stream.
    Data,
    /// Half-close: the sender will send no more data on the stream.
    EndOfStream,
    /// Cancels a stream in both directions at once.
    Cancel,
    /// Terminal size change.
    Resize,
    /// The terminal's process exited (a guest report).
    Exit,
}

impl Operation {
    pub const ALL: [Self; 21] = [
        Self::Challenge,
        Self::Hello,
        Self::Welcome,
        Self::Ping,
        Self::Pong,
        Self::Revoke,
        Self::Shutdown,
        Self::InitReport,
        Self::ProbeResult,
        Self::AllProbesPassed,
        Self::Close,
        Self::WindowUpdate,
        Self::StreamWindowUpdate,
        Self::Open,
        Self::Opened,
        Self::OpenRefused,
        Self::Data,
        Self::EndOfStream,
        Self::Cancel,
        Self::Resize,
        Self::Exit,
    ];

    pub const fn code(self) -> u8 {
        match self {
            Self::Hello => 0x01,
            Self::Welcome => 0x02,
            Self::Ping => 0x03,
            Self::Pong => 0x04,
            Self::Revoke => 0x05,
            Self::Shutdown => 0x06,
            Self::InitReport => 0x07,
            Self::ProbeResult => 0x08,
            Self::AllProbesPassed => 0x09,
            Self::Close => 0x0a,
            Self::WindowUpdate => 0x0b,
            Self::Challenge => 0x0c,
            Self::Open => 0x10,
            Self::Opened => 0x11,
            Self::OpenRefused => 0x12,
            Self::Data => 0x13,
            Self::EndOfStream => 0x14,
            Self::Cancel => 0x15,
            Self::Resize => 0x16,
            Self::Exit => 0x17,
            Self::StreamWindowUpdate => 0x18,
        }
    }

    /// The operation `code` names on `channel`, or `None` when no operation of the closed
    /// set has that code on that channel.
    pub fn decode(channel: Channel, code: u8) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|operation| operation.code() == code && operation.direction(channel).is_some())
    }

    /// The direction the operation may travel on `channel`, or `None` when it does not
    /// exist there. This table is the whole protocol surface.
    pub const fn direction(self, channel: Channel) -> Option<Direction> {
        use Channel::{Control, Egress, File, Ingress, Terminal};
        use Direction::{Both, GuestToHost, HostToGuest};
        match (self, channel) {
            (Self::Challenge, Control) => Some(HostToGuest),
            (Self::Hello, Control) => Some(GuestToHost),
            (Self::Welcome, Control) => Some(HostToGuest),
            (Self::Ping | Self::Pong, Control) => Some(Both),
            (Self::Revoke | Self::Shutdown, Control) => Some(HostToGuest),
            (Self::InitReport | Self::ProbeResult | Self::AllProbesPassed, Control) => {
                Some(GuestToHost)
            }
            (Self::Close, Control) => Some(Both),
            (Self::WindowUpdate, Terminal | File) => Some(Both),
            (Self::StreamWindowUpdate, Ingress | Egress) => Some(Both),
            (Self::Open, Terminal | Ingress) => Some(HostToGuest),
            (Self::Open, Egress) => Some(GuestToHost),
            (Self::Open, File) => Some(Both),
            (Self::Opened | Self::OpenRefused, Terminal | Ingress) => Some(GuestToHost),
            (Self::Opened | Self::OpenRefused, Egress) => Some(HostToGuest),
            (Self::Opened | Self::OpenRefused, File) => Some(Both),
            (Self::Data | Self::EndOfStream | Self::Cancel, Terminal | File | Ingress | Egress) => {
                Some(Both)
            }
            (Self::Resize, Terminal) => Some(HostToGuest),
            (Self::Exit, Terminal) => Some(GuestToHost),
            _ => None,
        }
    }

    pub const fn stream_use(self) -> StreamUse {
        match self {
            Self::Challenge
            | Self::Hello
            | Self::Welcome
            | Self::Ping
            | Self::Pong
            | Self::Revoke
            | Self::Shutdown
            | Self::InitReport
            | Self::ProbeResult
            | Self::AllProbesPassed
            | Self::Close
            | Self::WindowUpdate => StreamUse::None,
            Self::StreamWindowUpdate
            | Self::Open
            | Self::Opened
            | Self::OpenRefused
            | Self::Data
            | Self::EndOfStream
            | Self::Cancel
            | Self::Resize
            | Self::Exit => StreamUse::Required,
        }
    }

    /// Revocation and lifecycle control, sent before everything else queued (§3.2
    /// "priority for revocation/lifecycle control over bulk transfers").
    pub const fn is_urgent(self) -> bool {
        matches!(
            self,
            Self::Revoke | Self::Shutdown | Self::Close | Self::Welcome | Self::Challenge
        )
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::Challenge => "challenge",
            Self::Hello => "hello",
            Self::Welcome => "welcome",
            Self::Ping => "ping",
            Self::Pong => "pong",
            Self::Revoke => "revoke",
            Self::Shutdown => "shutdown",
            Self::InitReport => "init_report",
            Self::ProbeResult => "probe_result",
            Self::AllProbesPassed => "all_probes_passed",
            Self::Close => "close",
            Self::WindowUpdate => "window_update",
            Self::StreamWindowUpdate => "stream_window_update",
            Self::Open => "open",
            Self::Opened => "opened",
            Self::OpenRefused => "open_refused",
            Self::Data => "data",
            Self::EndOfStream => "end_of_stream",
            Self::Cancel => "cancel",
            Self::Resize => "resize",
            Self::Exit => "exit",
        }
    }
}

impl fmt::Display for Operation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// Why the framing layer refused bytes. Every one of these ends the link, because a byte
/// stream whose framing is wrong cannot be resynchronised (VM-P28 "malformed/oversized
/// IPC, incomplete frames").
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "framing", rename_all = "snake_case")]
pub enum FramingRefusal {
    BadMagic,
    /// Version 1, which bound a link to the boot only and carries no connection.
    RetiredVersion {
        found: u8,
    },
    UnsupportedVersion {
        found: u8,
    },
    UnknownChannel {
        code: u8,
    },
    ReservedFlags {
        flags: u8,
    },
    /// The header declares a frame longer than the fixed maximum; refused before any
    /// payload byte is buffered.
    Oversized {
        frame_bytes: u64,
        max_frame_bytes: u32,
    },
    /// The peer went away in the middle of a frame.
    Truncated {
        have_bytes: usize,
        need_bytes: usize,
    },
    /// Bytes arrived after the decoder was closed.
    DecoderClosed,
}

impl FramingRefusal {
    /// The stable name used by the conformance corpus.
    pub const fn code(self) -> &'static str {
        match self {
            Self::BadMagic => "framing.bad_magic",
            Self::RetiredVersion { .. } => "framing.retired_version",
            Self::UnsupportedVersion { .. } => "framing.unsupported_version",
            Self::UnknownChannel { .. } => "framing.unknown_channel",
            Self::ReservedFlags { .. } => "framing.reserved_flags",
            Self::Oversized { .. } => "framing.oversized",
            Self::Truncated { .. } => "framing.truncated",
            Self::DecoderClosed => "framing.decoder_closed",
        }
    }
}

impl fmt::Display for FramingRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadMagic => f.write_str("the frame does not start with the link magic"),
            Self::RetiredVersion { found } => write!(
                f,
                "protocol version {found} is retired: it binds no connection; the host speaks {PROTOCOL_VERSION}"
            ),
            Self::UnsupportedVersion { found } => {
                write!(f, "protocol version {found} is not {PROTOCOL_VERSION}")
            }
            Self::UnknownChannel { code } => write!(f, "channel code {code} is unknown"),
            Self::ReservedFlags { flags } => {
                write!(f, "flags {flags:#04x} are reserved and must be zero")
            }
            Self::Oversized {
                frame_bytes,
                max_frame_bytes,
            } => write!(
                f,
                "the frame is {frame_bytes} bytes, larger than {max_frame_bytes}"
            ),
            Self::Truncated {
                have_bytes,
                need_bytes,
            } => write!(
                f,
                "the peer closed after {have_bytes} of {need_bytes} bytes of a frame"
            ),
            Self::DecoderClosed => f.write_str("bytes arrived after the decoder closed"),
        }
    }
}

impl std::error::Error for FramingRefusal {}

/// The decoded fixed header of one frame. The operation stays a raw code until the frame
/// is authenticated; the typed [`Operation`] is resolved afterwards.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct FrameHeader {
    pub channel: Channel,
    pub operation_code: u8,
    pub stream: u32,
    pub sequence: u64,
    pub boot_generation: u64,
    pub payload_bytes: u32,
    pub connection: Connection,
}

impl FrameHeader {
    pub fn encode(&self) -> [u8; HEADER_BYTES] {
        let mut bytes = [0u8; HEADER_BYTES];
        bytes[0..4].copy_from_slice(&MAGIC);
        bytes[4] = PROTOCOL_VERSION;
        bytes[5] = self.channel.code();
        bytes[6] = self.operation_code;
        bytes[7] = 0;
        bytes[8..12].copy_from_slice(&self.stream.to_be_bytes());
        bytes[12..20].copy_from_slice(&self.sequence.to_be_bytes());
        bytes[20..28].copy_from_slice(&self.boot_generation.to_be_bytes());
        bytes[28..32].copy_from_slice(&self.payload_bytes.to_be_bytes());
        bytes[32..HEADER_BYTES].copy_from_slice(self.connection.as_bytes());
        bytes
    }

    /// Decodes a header, refusing a bad magic, the retired or another version, an unknown
    /// channel, reserved flags and a frame longer than `max_frame_bytes` (header, payload
    /// and tag together), in that order. The connection field is read as carried.
    pub fn decode(
        bytes: &[u8; HEADER_BYTES],
        max_frame_bytes: u32,
    ) -> Result<Self, FramingRefusal> {
        if bytes[0..4] != MAGIC {
            return Err(FramingRefusal::BadMagic);
        }
        if bytes[4] == RETIRED_PROTOCOL_VERSION {
            return Err(FramingRefusal::RetiredVersion { found: bytes[4] });
        }
        if bytes[4] != PROTOCOL_VERSION {
            return Err(FramingRefusal::UnsupportedVersion { found: bytes[4] });
        }
        let channel = Channel::from_code(bytes[5])
            .ok_or(FramingRefusal::UnknownChannel { code: bytes[5] })?;
        if bytes[7] != 0 {
            return Err(FramingRefusal::ReservedFlags { flags: bytes[7] });
        }
        let payload_bytes = u32::from_be_bytes([bytes[28], bytes[29], bytes[30], bytes[31]]);
        let mut connection = [0u8; CONNECTION_NONCE_BYTES];
        connection.copy_from_slice(&bytes[32..HEADER_BYTES]);
        let frame_bytes = u64::from(payload_bytes) + FRAME_OVERHEAD_BYTES as u64;
        if frame_bytes > u64::from(max_frame_bytes) {
            return Err(FramingRefusal::Oversized {
                frame_bytes,
                max_frame_bytes,
            });
        }
        Ok(Self {
            channel,
            operation_code: bytes[6],
            stream: u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]),
            sequence: u64::from_be_bytes([
                bytes[12], bytes[13], bytes[14], bytes[15], bytes[16], bytes[17], bytes[18],
                bytes[19],
            ]),
            boot_generation: u64::from_be_bytes([
                bytes[20], bytes[21], bytes[22], bytes[23], bytes[24], bytes[25], bytes[26],
                bytes[27],
            ]),
            payload_bytes,
            connection: Connection::from_bytes(connection),
        })
    }

    /// The whole frame length this header announces.
    pub fn frame_bytes(&self) -> usize {
        self.payload_bytes as usize + FRAME_OVERHEAD_BYTES
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header() -> FrameHeader {
        let mut connection = [0u8; CONNECTION_NONCE_BYTES];
        for (index, byte) in connection.iter_mut().enumerate() {
            *byte = index as u8 + 1;
        }
        FrameHeader {
            channel: Channel::Egress,
            operation_code: Operation::Data.code(),
            stream: 7,
            sequence: 99,
            boot_generation: 3,
            payload_bytes: 10,
            connection: Connection::from_bytes(connection),
        }
    }

    #[test]
    fn the_header_round_trips_and_is_48_bytes() {
        let header = header();
        let bytes = header.encode();
        assert_eq!(bytes.len(), HEADER_BYTES);
        assert_eq!(HEADER_BYTES, 48);
        assert_eq!(&bytes[0..4], b"YGLK");
        assert_eq!(bytes[4], 3);
        assert_eq!(&bytes[32..48], header.connection.as_bytes());
        assert_eq!(FrameHeader::decode(&bytes, 65_552), Ok(header));
        assert_eq!(header.frame_bytes(), 90);
    }

    #[test]
    fn version_1_is_refused_by_name_and_others_as_unsupported() {
        let mut bytes = header().encode();
        bytes[4] = RETIRED_PROTOCOL_VERSION;
        let retired = FrameHeader::decode(&bytes, 65_552).unwrap_err();
        assert_eq!(retired, FramingRefusal::RetiredVersion { found: 1 });
        assert_eq!(retired.code(), "framing.retired_version");
        assert!(retired.to_string().contains("retired"), "{retired}");
        for found in [0u8, 2, 4, 0xff] {
            bytes[4] = found;
            assert_eq!(
                FrameHeader::decode(&bytes, 65_552),
                Err(FramingRefusal::UnsupportedVersion { found })
            );
        }
    }

    #[test]
    fn every_code_decodes_only_where_the_table_allows() {
        for channel in Channel::ALL {
            for operation in Operation::ALL {
                let decoded = Operation::decode(channel, operation.code());
                match operation.direction(channel) {
                    Some(_) => assert_eq!(decoded, Some(operation), "{channel} {operation}"),
                    None => assert_ne!(decoded, Some(operation), "{channel} {operation}"),
                }
            }
            assert_eq!(Operation::decode(channel, 0x00), None);
            assert_eq!(Operation::decode(channel, 0x7f), None);
            assert_eq!(Operation::decode(channel, 0xff), None);
        }
        let codes: std::collections::BTreeSet<u8> = Operation::ALL
            .iter()
            .map(|operation| operation.code())
            .collect();
        assert_eq!(codes.len(), Operation::ALL.len());
    }

    #[test]
    fn channel_codes_round_trip() {
        for channel in Channel::ALL {
            assert_eq!(Channel::from_code(channel.code()), Some(channel));
            assert_eq!(channel.index(), channel.code() as usize);
        }
        assert_eq!(Channel::from_code(5), None);
        assert!(!Channel::Control.is_bulk());
        assert!(Channel::BULK.iter().all(|channel| channel.is_bulk()));
    }

    #[test]
    fn directions_allow_the_right_sender() {
        assert!(Direction::Both.allows(Sender::Host));
        assert!(Direction::Both.allows(Sender::Guest));
        assert!(Direction::HostToGuest.allows(Sender::Host));
        assert!(!Direction::HostToGuest.allows(Sender::Guest));
        assert!(!Direction::GuestToHost.allows(Sender::Host));
        assert!(Direction::GuestToHost.allows(Sender::Guest));
    }
}
