//! The egress port: where a boot's guest egress streams go (module docs in `mod.rs`: the
//! relay's guest transport, M06). The service moves bytes between the link's egress channel
//! and the port and parses nothing: the guest's bytes are the relay's to read, the relay's
//! answer is the guest's.

use serde::Serialize;

use crate::sandbox::link::{LinkName, StreamId};

/// What the port has for the guest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EgressInbound {
    /// Bytes for `stream`.
    Data { stream: StreamId, bytes: Vec<u8> },
    /// The port's side ended `stream` in order; the host ends its direction.
    End { stream: StreamId },
    /// The port's side failed; the host cancels `stream`.
    Cancel { stream: StreamId },
}

/// The guest-facing transport of one sandbox's relay, as the service drives it. Every call
/// returns at once; `poll` never blocks.
pub trait EgressPort: Send {
    /// The guest opened `stream` to `destination`. An error cancels the stream.
    fn opened(&mut self, stream: StreamId, destination: &LinkName) -> Result<(), String>;

    /// Bytes the guest sent on `stream`. An error cancels the stream.
    fn data(&mut self, stream: StreamId, bytes: &[u8]) -> Result<(), String>;

    /// The guest ended its direction of `stream`; the port may still answer.
    fn guest_ended(&mut self, stream: StreamId);

    /// `stream` is gone on the link (finished, cancelled, the link or the channels closed).
    fn ended(&mut self, stream: StreamId);

    /// What the port has for the guest now.
    fn poll(&mut self) -> Vec<EgressInbound>;

    /// How much this stream's bounded pending queue can accept now. Producers of
    /// large replies can wait without dropping a slow reader's stream.
    fn poll_ready(&mut self, _room: &dyn Fn(StreamId) -> usize) -> Vec<EgressInbound> {
        self.poll()
    }
}

/// The egress channel of a sandbox, as status shows it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct EgressView {
    /// A port is attached: guest opens are accepted.
    pub attached: bool,
    /// Egress streams open on the link now.
    pub open_streams: usize,
}
