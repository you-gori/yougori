//! What waits to go to the guest on the file channel, and its release as the link allows
//! (VM part §3.2 lines 2063–2066: "fixed maximum frame, message, stream and buffered-byte
//! counts", "explicit cancellation, timeout, backpressure and half-close behavior").
//!
//! Each stream's messages keep their order. A data message goes out only when the guest's
//! credit on the file channel covers it, and nothing goes out while the link's file queue
//! is full; streams take turns, one message each per round, so one large answer does not
//! hold back the opens and ends of other streams. Opens refused and cancels need no credit
//! and go first. The bytes waiting are counted, and the adapter stops taking guest messages
//! while they pass its bound, so the guest's own receive window holds the rest back.

use std::collections::{BTreeMap, VecDeque};

use crate::foundation::ids::Clock;
use crate::sandbox::link::{Channel, HostLink, HostMessage, SendRefusal, StreamId};

/// One message for a stream the adapter holds.
pub(super) enum OutItem {
    Opened,
    Data(Vec<u8>),
    End,
}

/// What a flush did besides sending.
#[derive(Default)]
pub(super) struct Flushed {
    /// Streams whose end went out.
    pub(super) ended: Vec<StreamId>,
    /// Streams the link refused a message for; their other messages were dropped.
    pub(super) dropped: Vec<(StreamId, SendRefusal)>,
}

/// The file channel's outbound messages.
#[derive(Default)]
pub(super) struct Outbound {
    streams: BTreeMap<StreamId, VecDeque<OutItem>>,
    control: VecDeque<HostMessage>,
    bytes: u64,
}

/// Whether the link's file queue takes one more frame.
fn has_room<L: Clock>(link: &HostLink<L>) -> bool {
    link.channel(Channel::File).queued_frames < link.limits().file.max_queued_frames as usize
}

fn length(bytes: &[u8]) -> u64 {
    u64::try_from(bytes.len()).unwrap_or(u64::MAX)
}

impl Outbound {
    /// Data bytes waiting.
    pub(super) fn bytes(&self) -> u64 {
        self.bytes
    }

    /// Whether nothing waits.
    pub(super) fn is_empty(&self) -> bool {
        self.streams.is_empty() && self.control.is_empty()
    }

    pub(super) fn push(&mut self, stream: StreamId, item: OutItem) {
        if let OutItem::Data(bytes) = &item {
            self.bytes = self.bytes.saturating_add(length(bytes));
        }
        self.streams.entry(stream).or_default().push_back(item);
    }

    /// A message that needs no credit and belongs to no stream the adapter holds: an open
    /// refused or a cancel.
    pub(super) fn push_control(&mut self, message: HostMessage) {
        self.control.push_back(message);
    }

    /// Drops what waits for `stream`.
    pub(super) fn forget(&mut self, stream: StreamId) {
        if let Some(queue) = self.streams.remove(&stream) {
            let dropped = queue.iter().fold(0u64, |total, item| match item {
                OutItem::Data(bytes) => total.saturating_add(length(bytes)),
                OutItem::Opened | OutItem::End => total,
            });
            self.bytes = self.bytes.saturating_sub(dropped);
        }
    }

    pub(super) fn clear(&mut self) {
        self.streams.clear();
        self.control.clear();
        self.bytes = 0;
    }

    /// Sends what the link takes now: the control messages, then the streams' messages in
    /// turns, each data message only within the guest's credit.
    pub(super) fn flush<L: Clock>(&mut self, link: &mut HostLink<L>) -> Flushed {
        let mut flushed = Flushed::default();
        while let Some(message) = self.control.pop_front() {
            if !has_room(link) {
                self.control.push_front(message);
                return flushed;
            }
            // A refused open or cancel the link no longer wants, such as for a stream it
            // already dropped, has nothing left to do.
            let _ = link.send(message);
        }
        loop {
            let mut progress = false;
            let ids: Vec<StreamId> = self.streams.keys().copied().collect();
            for stream in ids {
                if !has_room(link) {
                    return flushed;
                }
                let Some(queue) = self.streams.get_mut(&stream) else {
                    continue;
                };
                let Some(item) = queue.pop_front() else {
                    self.streams.remove(&stream);
                    continue;
                };
                let (message, sent_bytes, end) = match item {
                    OutItem::Opened => (
                        HostMessage::Opened {
                            channel: Channel::File,
                            stream,
                        },
                        0,
                        false,
                    ),
                    OutItem::End => (
                        HostMessage::EndOfStream {
                            channel: Channel::File,
                            stream,
                        },
                        0,
                        true,
                    ),
                    OutItem::Data(bytes) => {
                        let needed = length(&bytes);
                        if needed > link.channel(Channel::File).send_credit_bytes {
                            queue.push_front(OutItem::Data(bytes));
                            continue;
                        }
                        (
                            HostMessage::Data {
                                channel: Channel::File,
                                stream,
                                bytes,
                            },
                            needed,
                            false,
                        )
                    }
                };
                if queue.is_empty() {
                    self.streams.remove(&stream);
                }
                self.bytes = self.bytes.saturating_sub(sent_bytes);
                match link.send(message) {
                    Ok(()) => {
                        progress = true;
                        if end {
                            flushed.ended.push(stream);
                        }
                    }
                    Err(refusal) => {
                        self.forget(stream);
                        flushed.dropped.push((stream, refusal));
                    }
                }
            }
            if !progress {
                return flushed;
            }
        }
    }
}
