//! The strict chunked-body decoder of the request reader (VM §4.3: reject ambiguous
//! framing; RFC 9112 §7.1 read narrowly).
//!
//! A chunk size is one to [`MAX_CHUNK_SIZE_DIGITS`] hexadecimal digits followed directly by
//! CRLF. Chunk extensions, whitespace, bare line feeds, chunk data without its CRLF and any
//! trailer field are refused rather than skipped, because each is a place where two
//! parsers have been seen to disagree about where a body ends. The decoded body counts
//! against the reader's body limit before a chunk's data is accepted.

use super::reader::ReadRefusal;

/// The most hexadecimal digits a chunk size may have: enough for any `u64`.
pub const MAX_CHUNK_SIZE_DIGITS: u8 = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ChunkState {
    /// Reading the digits of a chunk size.
    Size {
        value: u64,
        digits: u8,
    },
    /// The CR after a chunk size was read; LF must follow.
    SizeLf {
        value: u64,
    },
    /// Copying chunk data.
    Data {
        remaining: u64,
    },
    /// Chunk data ended; CR must follow.
    DataCr,
    /// The CR after chunk data was read; LF must follow.
    DataLf,
    /// The last chunk was read; CR must follow, since trailers are refused.
    LastCr,
    /// The CR after the last chunk was read; LF must follow.
    LastLf,
    Done,
}

/// Decodes one chunked body incrementally.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct ChunkDecoder {
    state: ChunkState,
    decoded: u64,
}

impl ChunkDecoder {
    pub(super) const fn new() -> Self {
        Self {
            state: ChunkState::Size {
                value: 0,
                digits: 0,
            },
            decoded: 0,
        }
    }

    /// Consumes bytes of `input` until the body ends, appending decoded data to `body`.
    /// Returns how many bytes were consumed and whether the body is complete; bytes after
    /// the end are left unconsumed for the caller to judge.
    pub(super) fn consume(
        &mut self,
        input: &[u8],
        body: &mut Vec<u8>,
        max_body_bytes: u64,
    ) -> Result<(usize, bool), ReadRefusal> {
        let mut index = 0;
        while index < input.len() && self.state != ChunkState::Done {
            if let ChunkState::Data { remaining } = self.state {
                let available = input.len() - index;
                let take = usize::try_from(remaining).map_or(available, |r| r.min(available));
                body.extend_from_slice(&input[index..index + take]);
                index += take;
                let taken = u64::try_from(take).map_err(|_| ReadRefusal::InvalidChunkSize)?;
                let remaining = remaining.saturating_sub(taken);
                self.state = if remaining == 0 {
                    ChunkState::DataCr
                } else {
                    ChunkState::Data { remaining }
                };
                continue;
            }
            self.state = self.next_state(input[index], max_body_bytes)?;
            index += 1;
        }
        Ok((index, self.state == ChunkState::Done))
    }

    fn next_state(&mut self, byte: u8, max_body_bytes: u64) -> Result<ChunkState, ReadRefusal> {
        Ok(match self.state {
            ChunkState::Size { value, digits } => match byte {
                b';' => return Err(ReadRefusal::ChunkExtension),
                b'\r' if digits > 0 => ChunkState::SizeLf { value },
                _ => {
                    let digit = char::from(byte)
                        .to_digit(16)
                        .ok_or(ReadRefusal::InvalidChunkSize)?;
                    if digits >= MAX_CHUNK_SIZE_DIGITS {
                        return Err(ReadRefusal::InvalidChunkSize);
                    }
                    let value = value
                        .checked_mul(16)
                        .and_then(|value| value.checked_add(u64::from(digit)))
                        .ok_or(ReadRefusal::InvalidChunkSize)?;
                    ChunkState::Size {
                        value,
                        digits: digits + 1,
                    }
                }
            },
            ChunkState::SizeLf { value } => {
                if byte != b'\n' {
                    return Err(ReadRefusal::InvalidChunkSize);
                }
                if value == 0 {
                    ChunkState::LastCr
                } else {
                    let length = self.decoded.saturating_add(value);
                    if length > max_body_bytes {
                        return Err(ReadRefusal::BodyTooLarge {
                            limit: max_body_bytes,
                            length,
                        });
                    }
                    self.decoded = length;
                    ChunkState::Data { remaining: value }
                }
            }
            ChunkState::DataCr => match byte {
                b'\r' => ChunkState::DataLf,
                _ => return Err(ReadRefusal::ChunkNotTerminated),
            },
            ChunkState::DataLf => match byte {
                b'\n' => ChunkState::Size {
                    value: 0,
                    digits: 0,
                },
                _ => return Err(ReadRefusal::ChunkNotTerminated),
            },
            ChunkState::LastCr => match byte {
                b'\r' => ChunkState::LastLf,
                _ => return Err(ReadRefusal::Trailers),
            },
            ChunkState::LastLf => match byte {
                b'\n' => ChunkState::Done,
                _ => return Err(ReadRefusal::ChunkNotTerminated),
            },
            // `consume` copies data itself and stops at the end; neither reaches here.
            ChunkState::Data { .. } | ChunkState::Done => self.state,
        })
    }
}
