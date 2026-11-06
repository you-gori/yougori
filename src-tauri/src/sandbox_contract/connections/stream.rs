//! The stream port a session or connection moves bytes through (VM-W13). The socket or
//! transport adapter (M06/M02) implements it; tests use an in-memory duplex.

use std::fmt;

/// What one read found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StreamRead {
    /// This many bytes were read into the buffer, at least one.
    Bytes(usize),
    /// Nothing is ready now; the stream is still open.
    Idle,
    /// The peer closed its end; nothing more will arrive.
    Ended,
}

/// Why a stream operation failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StreamError {
    /// The stream, or its peer, is closed.
    Closed,
    /// The transport failed; the detail is the adapter's.
    Failed { detail: String },
}

impl fmt::Display for StreamError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Closed => f.write_str("the stream is closed"),
            Self::Failed { detail } => write!(f, "the stream failed: {detail}"),
        }
    }
}

impl std::error::Error for StreamError {}

/// One end of a byte stream, non-blocking and synchronous. The gate owns both ends of
/// every session and connection it admits and closes them when it ends the channel.
pub trait SessionStream: Send {
    /// Reads at most `buffer.len()` bytes that are ready now.
    fn read(&mut self, buffer: &mut [u8]) -> Result<StreamRead, StreamError>;

    /// Writes all of `bytes`, or fails without a partial write.
    fn write(&mut self, bytes: &[u8]) -> Result<(), StreamError>;

    /// Ends this end's writing (a half close, as TCP has): the peer reads
    /// [`StreamRead::Ended`] once it took every byte written before, and this end still reads
    /// what the peer sends. Writing afterwards fails; finishing twice, or after a close, does
    /// nothing.
    fn finish(&mut self);

    /// Closes this end: the peer reads [`StreamRead::Ended`] and its writes fail. Closing
    /// twice does nothing.
    fn close(&mut self);
}
