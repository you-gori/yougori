//! The link's wire frame (M09C; VM-W11 "bounded parsers"; VM part §3.1: the relay parses
//! bounded frames): a version, a body length, the body and its HMAC-SHA256 tag, read
//! incrementally within one hard size bound.
//!
//! ```text
//! version   u16, big-endian            LINK_PROTOCOL_VERSION
//! length    u32, big-endian            bytes of the body, at most MAX_BODY_BYTES
//! body      `length` bytes             the frame body, strict JSON (see the session)
//! tag       32 bytes                   HMAC-SHA256 under the session key
//! ```
//!
//! [`FrameDecoder`] refuses an unknown version from the first two bytes and an oversize
//! frame from its six-byte header, before any body byte is kept. It takes bytes only up
//! to the end of the frame it is reading, so it never holds more than one frame, and the
//! result does not depend on how the bytes were split. It authenticates nothing: the
//! session verifies the tag before it reads the body.

use super::session::LinkRefusal;
use crate::foundation::transfer::HMAC_SHA256_TAG_BYTES;

/// The link protocol version this build writes and reads. A frame of any other version
/// is refused from its first two bytes.
pub const LINK_PROTOCOL_VERSION: u16 = 1;

/// The most bytes one frame takes on the wire: header, body and tag. A frame that
/// declares more is refused from its header, before its body is read, and a message
/// whose frame would be larger is refused when sealed, never truncated.
pub const MAX_FRAME_BYTES: usize = 4 * 1024 * 1024;

/// Bytes before the body: the version and the body length.
pub const FRAME_HEADER_BYTES: usize = 6;

/// Bytes after the body: the HMAC-SHA256 tag.
pub const FRAME_TAG_BYTES: usize = HMAC_SHA256_TAG_BYTES;

/// The most bytes a frame's body takes.
pub const MAX_BODY_BYTES: usize = MAX_FRAME_BYTES - FRAME_HEADER_BYTES - FRAME_TAG_BYTES;

/// One complete frame of the current version as it arrived: untrusted until a session
/// verifies its tag.
#[derive(Clone, PartialEq, Eq)]
pub struct RawFrame {
    body: Vec<u8>,
    tag: [u8; FRAME_TAG_BYTES],
}

impl std::fmt::Debug for RawFrame {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "RawFrame({} body bytes)", self.body.len())
    }
}

impl RawFrame {
    /// The body as it arrived, not yet authenticated.
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// The tag as it arrived.
    pub fn tag(&self) -> &[u8; FRAME_TAG_BYTES] {
        &self.tag
    }

    /// The frame's wire bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>, LinkRefusal> {
        encode(&self.body, &self.tag)
    }
}

/// Writes one frame of the current version: header, `body` and `tag`.
pub(super) fn encode(body: &[u8], tag: &[u8; FRAME_TAG_BYTES]) -> Result<Vec<u8>, LinkRefusal> {
    let oversize = || LinkRefusal::Oversize {
        declared: u64::try_from(body.len())
            .unwrap_or(u64::MAX)
            .saturating_add(OVERHEAD_BYTES),
        max: MAX_FRAME_BYTES_U64,
    };
    if body.len() > MAX_BODY_BYTES {
        return Err(oversize());
    }
    let length = u32::try_from(body.len()).map_err(|_| oversize())?;
    let mut bytes = Vec::with_capacity(FRAME_HEADER_BYTES + body.len() + FRAME_TAG_BYTES);
    bytes.extend_from_slice(&LINK_PROTOCOL_VERSION.to_be_bytes());
    bytes.extend_from_slice(&length.to_be_bytes());
    bytes.extend_from_slice(body);
    bytes.extend_from_slice(tag);
    Ok(bytes)
}

/// Header and tag bytes, for the declared size of an oversize frame (a widening cast).
const OVERHEAD_BYTES: u64 = (FRAME_HEADER_BYTES + FRAME_TAG_BYTES) as u64;

/// [`MAX_FRAME_BYTES`] as reported in refusals (a widening cast).
const MAX_FRAME_BYTES_U64: u64 = MAX_FRAME_BYTES as u64;

/// Reads frames from a byte stream one at a time (see the module notes).
#[derive(Debug, Default)]
pub struct FrameDecoder {
    /// The frame being read: its header, then its body and tag.
    buffer: Vec<u8>,
    /// The whole frame's length, once its header is read and accepted.
    frame_bytes: Option<usize>,
    /// A refusal is final: the stream cannot be trusted to be in step after it.
    refused: Option<LinkRefusal>,
}

impl FrameDecoder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Takes bytes from `input` up to the end of the frame being read and returns how
    /// many it took; the caller feeds the rest after taking the frame. Takes nothing
    /// while a complete frame waits to be taken. A refusal is final.
    pub fn feed(&mut self, input: &[u8]) -> Result<usize, LinkRefusal> {
        if let Some(refusal) = &self.refused {
            return Err(refusal.clone());
        }
        let mut used = 0;
        if self.frame_bytes.is_none() {
            let wanted = FRAME_HEADER_BYTES.saturating_sub(self.buffer.len());
            let taken = wanted.min(input.len());
            self.buffer.extend_from_slice(&input[..taken]);
            used += taken;
            if let Err(refusal) = self.read_header() {
                self.buffer.clear();
                self.refused = Some(refusal.clone());
                return Err(refusal);
            }
        }
        let Some(frame_bytes) = self.frame_bytes else {
            return Ok(used);
        };
        let wanted = frame_bytes.saturating_sub(self.buffer.len());
        let rest = &input[used..];
        let taken = wanted.min(rest.len());
        self.buffer.extend_from_slice(&rest[..taken]);
        Ok(used + taken)
    }

    /// The complete frame, once all of it was fed; the decoder then reads the next.
    pub fn take(&mut self) -> Option<RawFrame> {
        let frame_bytes = self.frame_bytes?;
        if self.buffer.len() < frame_bytes {
            return None;
        }
        let tag_start = frame_bytes - FRAME_TAG_BYTES;
        let mut tag = [0u8; FRAME_TAG_BYTES];
        tag.copy_from_slice(&self.buffer[tag_start..frame_bytes]);
        let body = self.buffer[FRAME_HEADER_BYTES..tag_start].to_vec();
        self.buffer.clear();
        self.frame_bytes = None;
        Some(RawFrame { body, tag })
    }

    /// True when no part of a frame is held: the stream may end here without cutting a
    /// frame short.
    pub fn is_between_frames(&self) -> bool {
        self.buffer.is_empty() && self.refused.is_none()
    }

    /// The refusal that ended the stream, if any.
    pub fn refusal(&self) -> Option<&LinkRefusal> {
        self.refused.as_ref()
    }

    /// Checks the version as soon as its two bytes are in, then the length once the
    /// whole header is.
    fn read_header(&mut self) -> Result<(), LinkRefusal> {
        if self.buffer.len() >= 2 {
            let found = u16::from_be_bytes([self.buffer[0], self.buffer[1]]);
            if found != LINK_PROTOCOL_VERSION {
                return Err(LinkRefusal::UnknownVersion { found });
            }
        }
        if self.buffer.len() < FRAME_HEADER_BYTES {
            return Ok(());
        }
        let length = u32::from_be_bytes([
            self.buffer[2],
            self.buffer[3],
            self.buffer[4],
            self.buffer[5],
        ]);
        let declared = u64::from(length).saturating_add(OVERHEAD_BYTES);
        let oversize = LinkRefusal::Oversize {
            declared,
            max: MAX_FRAME_BYTES_U64,
        };
        let body = usize::try_from(length).map_err(|_| oversize.clone())?;
        if body > MAX_BODY_BYTES {
            return Err(oversize);
        }
        if body == 0 {
            return Err(LinkRefusal::EmptyBody);
        }
        self.frame_bytes = Some(FRAME_HEADER_BYTES + body + FRAME_TAG_BYTES);
        Ok(())
    }
}
