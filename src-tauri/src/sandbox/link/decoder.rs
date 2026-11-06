//! The frame decoder: a pure state machine fed bytes incrementally, holding at most one
//! frame, so memory stays bounded whatever the peer sends (VM-P28 "malformed/oversized
//! IPC, incomplete frames, slow peers ... remain bounded"). There is no recursion: a push
//! is one loop over the input.

use serde::Serialize;

use crate::foundation::ids::MonotonicTime;

use super::wire::{FrameHeader, FramingRefusal, HEADER_BYTES, TAG_BYTES};

/// One authenticated-later frame as the decoder delimited it: the header, its exact
/// bytes (the tag covers them), the payload and the tag.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RawFrame {
    pub header: FrameHeader,
    pub header_bytes: [u8; HEADER_BYTES],
    pub payload: Vec<u8>,
    pub tag: [u8; TAG_BYTES],
}

/// What one push produced.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DecodeStep {
    Frame(RawFrame),
    /// The decoder closed on this; no later byte is read.
    Refused(FramingRefusal),
}

/// The decoder's phase.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "decoder", rename_all = "snake_case")]
pub enum DecoderPhase {
    /// Collecting header bytes.
    Header {
        have_bytes: usize,
    },
    /// Collecting the payload and tag of a frame whose header was accepted.
    Body {
        have_bytes: usize,
        need_bytes: usize,
    },
    Closed(FramingRefusal),
}

/// The frame decoder of one direction.
#[derive(Clone, Debug)]
pub struct FrameDecoder {
    max_frame_bytes: u32,
    buffer: Vec<u8>,
    header: Option<FrameHeader>,
    need_bytes: usize,
    started_at: Option<MonotonicTime>,
    closed: Option<FramingRefusal>,
}

impl FrameDecoder {
    pub fn new(max_frame_bytes: u32) -> Self {
        Self {
            max_frame_bytes,
            buffer: Vec::with_capacity(HEADER_BYTES),
            header: None,
            need_bytes: HEADER_BYTES,
            started_at: None,
            closed: None,
        }
    }

    pub fn phase(&self) -> DecoderPhase {
        match (self.closed, self.header) {
            (Some(refusal), _) => DecoderPhase::Closed(refusal),
            (None, None) => DecoderPhase::Header {
                have_bytes: self.buffer.len(),
            },
            (None, Some(_)) => DecoderPhase::Body {
                have_bytes: self.buffer.len(),
                need_bytes: self.need_bytes,
            },
        }
    }

    pub fn is_closed(&self) -> bool {
        self.closed.is_some()
    }

    /// Bytes held right now; never above the frame limit.
    pub fn buffered_bytes(&self) -> usize {
        self.buffer.len()
    }

    /// When the partial frame being collected started, for the slow-peer timeout.
    pub fn partial_since(&self) -> Option<MonotonicTime> {
        if self.buffer.is_empty() {
            None
        } else {
            self.started_at
        }
    }

    /// Feeds `bytes`, received at `now`. Complete frames come out in order; the first
    /// framing refusal closes the decoder and ends the push.
    pub fn push(&mut self, bytes: &[u8], now: MonotonicTime) -> Vec<DecodeStep> {
        let mut steps = Vec::new();
        if self.closed.is_some() {
            if !bytes.is_empty() {
                steps.push(DecodeStep::Refused(FramingRefusal::DecoderClosed));
            }
            return steps;
        }
        let mut cursor = 0usize;
        while cursor < bytes.len() {
            if self.buffer.is_empty() {
                self.started_at = Some(now);
            }
            let take = (self.need_bytes - self.buffer.len()).min(bytes.len() - cursor);
            let Some(piece) = bytes.get(cursor..cursor + take) else {
                break;
            };
            self.buffer.extend_from_slice(piece);
            cursor += take;
            if self.buffer.len() < self.need_bytes {
                continue;
            }
            match self.header {
                None => {
                    let mut header_bytes = [0u8; HEADER_BYTES];
                    header_bytes.copy_from_slice(&self.buffer);
                    match FrameHeader::decode(&header_bytes, self.max_frame_bytes) {
                        Ok(header) => {
                            self.header = Some(header);
                            self.need_bytes = header.frame_bytes();
                            if self.buffer.len() >= self.need_bytes {
                                steps.push(DecodeStep::Frame(self.take_frame(header)));
                            }
                        }
                        Err(refusal) => {
                            self.close(refusal);
                            steps.push(DecodeStep::Refused(refusal));
                            return steps;
                        }
                    }
                }
                Some(header) => steps.push(DecodeStep::Frame(self.take_frame(header))),
            }
        }
        steps
    }

    /// The peer went away. A partial frame is a truncation refusal; nothing pending is
    /// fine. Either way the decoder closes.
    pub fn finish(&mut self) -> Option<FramingRefusal> {
        if self.closed.is_some() {
            return None;
        }
        let refusal = if self.buffer.is_empty() {
            None
        } else {
            Some(FramingRefusal::Truncated {
                have_bytes: self.buffer.len(),
                need_bytes: self.need_bytes,
            })
        };
        self.close(refusal.unwrap_or(FramingRefusal::DecoderClosed));
        refusal
    }

    /// Closes the decoder; later bytes are refused.
    pub fn close(&mut self, refusal: FramingRefusal) {
        self.closed = Some(refusal);
        self.buffer = Vec::new();
        self.header = None;
        self.need_bytes = HEADER_BYTES;
        self.started_at = None;
    }

    fn take_frame(&mut self, header: FrameHeader) -> RawFrame {
        let frame = std::mem::take(&mut self.buffer);
        let payload_end = HEADER_BYTES + header.payload_bytes as usize;
        let mut header_bytes = [0u8; HEADER_BYTES];
        let mut tag = [0u8; TAG_BYTES];
        let payload = match (
            frame.get(..HEADER_BYTES),
            frame.get(HEADER_BYTES..payload_end),
            frame.get(payload_end..payload_end + TAG_BYTES),
        ) {
            (Some(head), Some(payload), Some(tail)) => {
                header_bytes.copy_from_slice(head);
                tag.copy_from_slice(tail);
                payload.to_vec()
            }
            _ => Vec::new(),
        };
        self.header = None;
        self.need_bytes = HEADER_BYTES;
        self.started_at = None;
        self.buffer = Vec::with_capacity(HEADER_BYTES);
        RawFrame {
            header,
            header_bytes,
            payload,
            tag,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::foundation::ids::MonotonicTime;
    use crate::sandbox::link::wire::{Channel, Operation, FRAME_OVERHEAD_BYTES, MAGIC};

    const MAX: u32 = 256;

    fn frame(payload: &[u8]) -> Vec<u8> {
        let header = FrameHeader {
            channel: Channel::Control,
            operation_code: Operation::Ping.code(),
            stream: 0,
            sequence: 1,
            boot_generation: 1,
            payload_bytes: payload.len() as u32,
            connection: crate::sandbox::link::connection::Connection::UNCHALLENGED,
        };
        let mut bytes = header.encode().to_vec();
        bytes.extend_from_slice(payload);
        bytes.extend_from_slice(&[0xabu8; TAG_BYTES]);
        bytes
    }

    fn now() -> MonotonicTime {
        MonotonicTime::from_nanos(5)
    }

    #[test]
    fn one_push_and_one_byte_at_a_time_give_the_same_frames() {
        let bytes = [frame(b"abc"), frame(b""), frame(&[7u8; 100])].concat();
        let mut whole = FrameDecoder::new(MAX);
        let all = whole.push(&bytes, now());
        let mut slow = FrameDecoder::new(MAX);
        let mut collected = Vec::new();
        let mut peak = 0;
        for byte in &bytes {
            collected.extend(slow.push(std::slice::from_ref(byte), now()));
            peak = peak.max(slow.buffered_bytes());
        }
        assert_eq!(all, collected);
        assert_eq!(all.len(), 3);
        assert!(peak <= MAX as usize);
        match &all[0] {
            DecodeStep::Frame(raw) => {
                assert_eq!(raw.payload, b"abc");
                assert_eq!(raw.tag, [0xab; TAG_BYTES]);
                assert_eq!(&raw.header_bytes[0..4], &MAGIC);
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(slow.partial_since(), None);
        assert_eq!(slow.phase(), DecoderPhase::Header { have_bytes: 0 });
    }

    #[test]
    fn an_oversized_header_closes_before_any_payload_is_buffered() {
        let mut decoder = FrameDecoder::new(MAX);
        let mut bytes = frame(b"");
        bytes[28..32].copy_from_slice(&(MAX + 1).to_be_bytes());
        let steps = decoder.push(&bytes, now());
        assert_eq!(
            steps,
            vec![DecodeStep::Refused(FramingRefusal::Oversized {
                frame_bytes: u64::from(MAX) + 1 + FRAME_OVERHEAD_BYTES as u64,
                max_frame_bytes: MAX
            })]
        );
        assert!(decoder.is_closed());
        assert_eq!(decoder.buffered_bytes(), 0);
        assert_eq!(
            decoder.push(b"x", now()),
            vec![DecodeStep::Refused(FramingRefusal::DecoderClosed)]
        );
        assert_eq!(decoder.push(b"", now()), vec![]);
    }

    #[test]
    fn a_truncated_frame_is_reported_when_the_peer_goes_away() {
        let mut decoder = FrameDecoder::new(MAX);
        let bytes = frame(b"hello");
        let have_bytes = HEADER_BYTES + 3;
        assert_eq!(decoder.push(&bytes[..have_bytes], now()), vec![]);
        assert_eq!(
            decoder.phase(),
            DecoderPhase::Body {
                have_bytes,
                need_bytes: bytes.len()
            }
        );
        assert_eq!(decoder.partial_since(), Some(now()));
        assert_eq!(
            decoder.finish(),
            Some(FramingRefusal::Truncated {
                have_bytes,
                need_bytes: bytes.len()
            })
        );
        assert!(decoder.is_closed());

        let mut short = FrameDecoder::new(MAX);
        assert_eq!(short.push(&bytes[..10], now()), vec![]);
        assert_eq!(
            short.finish(),
            Some(FramingRefusal::Truncated {
                have_bytes: 10,
                need_bytes: HEADER_BYTES
            })
        );
        let mut clean = FrameDecoder::new(MAX);
        assert_eq!(clean.finish(), None);
        assert!(clean.is_closed());
    }

    #[test]
    fn bad_magic_version_channel_and_flags_each_close() {
        for (offset, value, expected) in [
            (0, b'X', FramingRefusal::BadMagic),
            (4, 1, FramingRefusal::RetiredVersion { found: 1 }),
            (4, 2, FramingRefusal::UnsupportedVersion { found: 2 }),
            (4, 4, FramingRefusal::UnsupportedVersion { found: 4 }),
            (5, 9, FramingRefusal::UnknownChannel { code: 9 }),
            (7, 1, FramingRefusal::ReservedFlags { flags: 1 }),
        ] {
            let mut bytes = frame(b"");
            bytes[offset] = value;
            let mut decoder = FrameDecoder::new(MAX);
            assert_eq!(
                decoder.push(&bytes, now()),
                vec![DecodeStep::Refused(expected)]
            );
            assert_eq!(decoder.phase(), DecoderPhase::Closed(expected));
        }
    }

    #[test]
    fn the_largest_allowed_frame_is_accepted_whole() {
        let payload = vec![1u8; MAX as usize - FRAME_OVERHEAD_BYTES];
        let mut decoder = FrameDecoder::new(MAX);
        let steps = decoder.push(&frame(&payload), now());
        assert!(matches!(&steps[..], [DecodeStep::Frame(raw)] if raw.payload == payload));
    }
}
