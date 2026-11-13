//! The site each connection asks for, checked on the host for the Sandbox VM network filter
//! (`network_filter`).
//!
//! A target named by its host name is held to the addresses that name had at launch, and
//! other sites may be served at those addresses too (a CDN, shared hosting, a cloud load
//! balancer). So a TCP connection to such an address and port (unless the person named that
//! address itself) is read before any of its bytes leave: the guest's bytes are held until
//! the connection says which site it is for, and go on only when that is a host the person
//! named, at this address and on this port.
//!
//! - **HTTPS (TLS)**: the server name of the ClientHello (SNI). A ClientHello that names no
//!   site is refused too: the server would answer with its default site and then serve
//!   whatever site the encrypted request names.
//! - **Plain HTTP**: the Host of every request on the connection, and the host of a request
//!   in absolute form. A request that names no site reaches only the server's default site,
//!   so it passes. Requests are read strictly, so that a server never reads a request the
//!   filter did not: anything ambiguous (two Host or Content-Length fields, a
//!   Transfer-Encoding other than chunked, folded or bare line ends, chunk extensions or
//!   trailers, an upgrade, CONNECT) refuses the connection.
//! - **Every other protocol** (its first line is no HTTP request and its first bytes are no
//!   ClientHello): it names no site, so it reaches whatever answers at that address and port,
//!   as for a target named by its address. A web server closes a connection whose first line
//!   is no request, so this never reaches another web site.
//!
//! QEMU's user network ends the guest's TCP connections itself and opens its own to the
//! destination, carrying only the bytes of the stream. So the filter holds back bytes, never
//! the handshake, and a refused connection is reset on both sides (the guest's, and the user
//! network's, which closes its connection to the server) before any of its bytes left. What
//! the server reads stays what the filter read: bytes go on only in stream order, segments
//! with a bad checksum or without an acknowledgement are dropped (the user network would drop
//! them and take a later copy), urgent data is refused before the decision, and a copy the
//! guest sends again must equal what was read. A connection's bytes count only once the user
//! network answered exactly the SYN that opened it ([`Handshakes`]): so no byte ever goes into
//! an older connection of the user network that the filter no longer follows, whatever
//! segments the guest makes up.
//!
//! What this cannot see: inside TLS, a server that serves another site than the one its
//! ClientHello named (domain fronting) is not stopped.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use super::{checksum, frame_onward, frame_to_guest, Ipv4, Verdict, TCP};

const FIN: u8 = 0x01;
const SYN: u8 = 0x02;
const RST: u8 = 0x04;
const ACK: u8 = 0x10;
const URG: u8 = 0x20;

/// Most bytes a connection may send before it says what it is (a ClientHello, an HTTP
/// request's head or another protocol's first line), and most bytes of one request head.
const MAX_OPENING: usize = 32 * 1024;
const MAX_HEAD: usize = 16 * 1024;
const MAX_LINE: usize = 8 * 1024;
/// Most frames held for one connection while it has not said what it is.
const MAX_HELD_FRAMES: usize = 64;
/// How far back the guest may send bytes again: the user network's largest receive window
/// (it scales no window), so older bytes are all acknowledged.
const HORIZON: u64 = 65535;
/// Pieces of kept bytes grow to this size before a new piece starts, so whole pieces age out.
const KEPT_PIECE: usize = 4096;
/// Most connections followed at once, and most bytes held and kept for all of them; beyond
/// that the least recently used connection is forgotten, or the growing one refused.
const MAX_CONNECTIONS: usize = 4096;
const BUDGET: usize = 32 << 20;
/// How long a quiet connection is remembered: one still open, and one closed or refused.
const IDLE: Duration = Duration::from_secs(2 * 60 * 60);
const CLOSED_IDLE: Duration = Duration::from_secs(60);
const SWEEP: Duration = Duration::from_secs(1);
/// How long the user network's answer to a SYN waits for the guest's next segment.
const HANDSHAKE_IDLE: Duration = Duration::from_secs(120);

/// Bytes that may come before a request line (and that a server skips): CR, LF and the
/// whitespace some servers take as such.
fn blank(byte: u8) -> bool {
    matches!(byte, b'\r' | b'\n' | b' ' | b'\t' | 0x0b | 0x0c)
}

/// A token character of HTTP (RFC 9110 `tchar`).
fn tchar(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte)
}

/// One guest TCP connection: the guest's address and port, then the destination's.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct Key {
    source: [u8; 4],
    source_port: u16,
    destination: [u8; 4],
    destination_port: u16,
}

/// One TCP segment the guest sent, as the filter reads it.
struct Segment<'a> {
    frame: &'a [u8],
    transport: &'a [u8],
    key: Key,
    sequence: u32,
    acknowledgement: u32,
    flags: u8,
    payload: &'a [u8],
}

impl<'a> Segment<'a> {
    /// `packet` is a TCP segment whose header length was checked (`Ipv4::ports`).
    fn parse(frame: &'a [u8], packet: &Ipv4<'a>) -> Option<Self> {
        let transport = packet.transport;
        let (source_port, destination_port) = packet.ports()?;
        let header = usize::from(transport[12] >> 4) * 4;
        Some(Self {
            frame,
            transport,
            key: Key {
                source: packet.source,
                source_port,
                destination: packet.destination,
                destination_port,
            },
            sequence: u32::from_be_bytes(transport[4..8].try_into().ok()?),
            acknowledgement: u32::from_be_bytes(transport[8..12].try_into().ok()?),
            flags: transport[13],
            payload: &transport[header..],
        })
    }

    /// Whether the IPv4 header's and the TCP segment's checksums hold, as the user network
    /// checks them.
    fn checksums_hold(&self) -> bool {
        let Ok(length) = u16::try_from(self.transport.len()) else {
            return false;
        };
        checksum(&[&self.frame[14..34]]) == 0
            && checksum(&[
                &self.key.source[..],
                &self.key.destination[..],
                &[0, TCP][..],
                &length.to_be_bytes()[..],
                self.transport,
            ]) == 0
    }
}

/// A TCP segment without options or payload, its checksum filled in.
fn tcp_segment(key: Key, sequence: u32, acknowledgement: u32, flags: u8) -> Vec<u8> {
    tcp_segment_window(key, sequence, acknowledgement, flags, 0)
}

/// A TCP segment without options or payload that offers `window`, its checksum filled in.
fn tcp_segment_window(key: Key, sequence: u32, acknowledgement: u32, flags: u8, window: u16) -> Vec<u8> {
    let mut segment = vec![0u8; 20];
    segment[0..2].copy_from_slice(&key.source_port.to_be_bytes());
    segment[2..4].copy_from_slice(&key.destination_port.to_be_bytes());
    segment[4..8].copy_from_slice(&sequence.to_be_bytes());
    segment[8..12].copy_from_slice(&acknowledgement.to_be_bytes());
    segment[12] = 0x50;
    segment[13] = flags;
    segment[14..16].copy_from_slice(&window.to_be_bytes());
    let sum = checksum(&[&key.source[..], &key.destination[..], &[0, TCP, 0, 20][..], &segment[..]]);
    segment[16..18].copy_from_slice(&sum.to_be_bytes());
    segment
}

/// A reset back to the guest from the destination, at the place the guest's own segment
/// says it has reached (its acknowledgement), so the guest takes it at once.
fn reset_guest(segment: &Segment<'_>) -> Vec<u8> {
    let key = segment.key;
    let back = Key {
        source: key.destination,
        source_port: key.destination_port,
        destination: key.source,
        destination_port: key.source_port,
    };
    let sequence = if segment.flags & ACK != 0 { segment.acknowledgement } else { 0 };
    let consumed = u32::try_from(segment.payload.len()).unwrap_or(0) + u32::from(segment.flags & (SYN | FIN) != 0);
    let transport = tcp_segment(back, sequence, segment.sequence.wrapping_add(consumed), RST | ACK);
    frame_to_guest(segment.frame, key.destination, key.source, TCP, &transport)
}

/// A reset on to the user network from the guest at `sequence`, the next byte the user
/// network expects, so it closes its connection to the server.
fn reset_network(segment: &Segment<'_>, sequence: u32) -> Vec<u8> {
    let key = segment.key;
    frame_onward(segment.frame, key.source, key.destination, TCP, &tcp_segment(key, sequence, 0, RST))
}

/// How far a connection's bytes have been read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    /// Nothing decided: its first bytes are being read.
    Opening,
    /// Plain HTTP, read request by request.
    Http(Http),
    /// Decided for the whole connection (TLS after its ClientHello, another protocol after
    /// its first line): bytes from `from` on pass unread.
    Open { from: u64 },
    /// Refused: nothing more goes on, and the guest is answered with resets.
    Refused,
}

/// Where a plain HTTP connection is in its stream of requests.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Http {
    /// At a request's head (held until read whole).
    Head,
    /// Within a body of this many bytes still to come.
    Body(u64),
    /// Within a chunk-size line of a chunked body: its digits so far, their value, and
    /// whether its CR came.
    Size { digits: u8, value: u64, cr: bool },
    /// Within a chunk of this many bytes still to come.
    Data(u64),
    /// At the CRLF after a chunk's data.
    DataEnd { cr: bool },
    /// At the CRLF that ends a chunked body (trailers are refused).
    Last { cr: bool },
}

/// What a connection's new bytes come to.
enum Step {
    /// Every byte so far is decided and may go on.
    Pass,
    /// The connection has not yet said what it is: hold its bytes.
    Hold,
    Refuse,
}

/// What becomes of one segment of a followed connection.
enum Outcome {
    Forward,
    Drop,
    /// Kept from the user network; this acknowledgement goes back to the guest instead.
    Answer(Vec<u8>),
    /// Held, with the acknowledgement of the bytes held, when the filter gives one.
    Held(Option<Vec<u8>>),
    Release(Vec<Vec<u8>>),
    Refuse,
}

struct Connection {
    /// The sequence number of the stream's first byte: the guest's initial one plus one.
    start: u32,
    /// The stream position of the next byte expected, and of the first byte not yet let
    /// through (every frame before it went on).
    next: u64,
    released: u64,
    /// The frames held, in order, and their bytes.
    held: Vec<Vec<u8>>,
    held_bytes: usize,
    /// The bytes not yet decided: the stream's last ones, up to `next`.
    pending: Vec<u8>,
    /// The bytes decisions read (heads, framing, the opening), by stream position, while
    /// the guest may still send them again.
    kept: VecDeque<(u64, Vec<u8>)>,
    kept_bytes: usize,
    phase: Phase,
    /// When its SYN came, whether the user network has since answered that SYN, and the
    /// window its answer offered (`None` when it scales its window).
    opened: Instant,
    confirmed: bool,
    window: Option<u16>,
    closing: bool,
    seen: Instant,
}

impl Connection {
    fn new(start: u32, now: Instant) -> Self {
        Self {
            start,
            next: 0,
            released: 0,
            held: Vec::new(),
            held_bytes: 0,
            pending: Vec::new(),
            kept: VecDeque::new(),
            kept_bytes: 0,
            phase: Phase::Opening,
            opened: now,
            confirmed: false,
            window: None,
            closing: false,
            seen: now,
        }
    }

    fn usage(&self) -> usize {
        self.held_bytes + self.pending.len() + self.kept_bytes
    }

    /// The stream position `sequence` stands for, near the next one expected; `None`
    /// before the stream's start.
    fn position(&self, sequence: u32) -> Option<u64> {
        let relative = sequence.wrapping_sub(self.start);
        // The low 32 bits are what wrap; the distance from `next` is what counts.
        let distance = relative.wrapping_sub(self.next as u32) as i32;
        u64::try_from(i64::try_from(self.next).ok()? + i64::from(distance)).ok()
    }

    /// Whether `bytes`, at stream position `position`, equal what was read there.
    fn matches(&self, position: u64, bytes: &[u8]) -> bool {
        let end = position + bytes.len() as u64;
        let pending_from = self.next - self.pending.len() as u64;
        let read = self
            .kept
            .iter()
            .map(|(at, kept)| (*at, kept.as_slice()))
            .chain(std::iter::once((pending_from, self.pending.as_slice())));
        for (at, kept) in read {
            let from = position.max(at);
            let to = end.min(at + kept.len() as u64);
            if from < to {
                let mine = &kept[(from - at) as usize..(to - at) as usize];
                let theirs = &bytes[(from - position) as usize..(to - position) as usize];
                if mine != theirs {
                    return false;
                }
            }
        }
        true
    }

    /// One segment of this connection, no SYN or RST; when it carries bytes, the end of the
    /// stream or urgent data, its checksums hold.
    fn segment(&mut self, segment: &Segment<'_>, may: &dyn Fn(&str) -> bool) -> Outcome {
        let fin = segment.flags & FIN != 0;
        let urgent = segment.flags & URG != 0;
        if segment.payload.is_empty() && !fin && !urgent {
            // An acknowledgement, a window update or a keep-alive: no bytes.
            return Outcome::Forward;
        }
        let Some(position) = self.position(segment.sequence) else {
            return Outcome::Drop;
        };
        let length = segment.payload.len() as u64;
        let end = position + length;
        // An urgent mark takes a byte out of the server's stream: never on bytes read for a
        // decision, so only after the opening of a connection read no further.
        if urgent && !matches!(self.phase, Phase::Open { from } if position >= from) {
            return Outcome::Refuse;
        }
        if length == 0 {
            if !fin {
                return Outcome::Forward;
            }
            if position != self.next {
                return Outcome::Drop;
            }
            if !self.pending.is_empty() {
                // Its stream ends before it said what it is for.
                return Outcome::Refuse;
            }
            self.closing = true;
            return Outcome::Forward;
        }
        // A gap (never on this link), or bytes older than any the guest may send again.
        if position > self.next || position + HORIZON < self.next {
            return Outcome::Drop;
        }
        let old = usize::try_from(self.next.min(end) - position).unwrap_or(usize::MAX);
        if !self.matches(position, &segment.payload[..old]) {
            return Outcome::Refuse;
        }
        if end <= self.next {
            // Bytes sent again: on when what they repeat went on; else the held frames carry
            // them already, and the guest hears again that they arrived.
            if end <= self.released {
                return Outcome::Forward;
            }
            return self.acknowledgement(segment).map_or(Outcome::Drop, Outcome::Answer);
        }
        match self.feed(&segment.payload[old..], may) {
            Step::Refuse => Outcome::Refuse,
            Step::Hold if fin || self.held.len() >= MAX_HELD_FRAMES => Outcome::Refuse,
            Step::Hold => {
                self.held_bytes += segment.frame.len();
                self.held.push(segment.frame.to_vec());
                Outcome::Held(self.acknowledgement(segment))
            }
            Step::Pass => {
                self.closing |= fin;
                self.released = self.next;
                if self.held.is_empty() {
                    Outcome::Forward
                } else {
                    let mut frames = std::mem::take(&mut self.held);
                    self.held_bytes = 0;
                    frames.push(segment.frame.to_vec());
                    Outcome::Release(frames)
                }
            }
        }
    }

    /// The acknowledgement of every byte so far, to the guest as if from the user network,
    /// while the connection's opening is held: a guest that waits for one before it sends
    /// more (Nagle's algorithm holds a small write back while an earlier one is unanswered)
    /// would otherwise never say what the connection is for. Only while nothing of the
    /// connection has reached the user network, which then has its whole first window free
    /// for the bytes held (it takes them all when they are released, and every released
    /// frame is queued for it), and never beyond that window. `segment` says where the
    /// guest is in the user network's own stream.
    fn acknowledgement(&self, segment: &Segment<'_>) -> Option<Vec<u8>> {
        let window = u64::from(self.window?);
        if self.released != 0 || self.next > window {
            return None;
        }
        let key = segment.key;
        let back = Key {
            source: key.destination,
            source_port: key.destination_port,
            destination: key.source,
            destination_port: key.source_port,
        };
        let offered = u16::try_from(window - self.next).unwrap_or(0);
        let acknowledged = self.start.wrapping_add(self.next as u32);
        let transport = tcp_segment_window(back, segment.acknowledgement, acknowledged, ACK, offered);
        Some(frame_to_guest(segment.frame, key.destination, key.source, TCP, &transport))
    }

    /// Reads the stream's next bytes, `fresh`, which start at `next`.
    fn feed(&mut self, fresh: &[u8], may: &dyn Fn(&str) -> bool) -> Step {
        self.next += fresh.len() as u64;
        let step = match self.phase {
            Phase::Open { .. } => Step::Pass,
            Phase::Refused => Step::Refuse,
            Phase::Opening | Phase::Http(_) => {
                self.pending.extend_from_slice(fresh);
                self.read(may)
            }
        };
        self.prune();
        step
    }

    /// Decides what it can of the pending bytes, from the front.
    fn read(&mut self, may: &dyn Fn(&str) -> bool) -> Step {
        loop {
            if self.pending.is_empty() {
                return Step::Pass;
            }
            match self.phase {
                Phase::Refused => return Step::Refuse,
                Phase::Open { .. } => {
                    self.pending.clear();
                    return Step::Pass;
                }
                Phase::Opening => match opening(&self.pending) {
                    Opening::Need => return self.wait(MAX_OPENING),
                    Opening::Refuse => return Step::Refuse,
                    Opening::Tls { length, name } => {
                        if !name.as_deref().is_some_and(may) {
                            return Step::Refuse;
                        }
                        return self.open(length);
                    }
                    Opening::Other { length } => return self.open(length),
                    Opening::Http => self.phase = Phase::Http(Http::Head),
                },
                Phase::Http(Http::Head) => match request_head(&self.pending, may) {
                    Head::Need => return self.wait(MAX_HEAD),
                    Head::Refuse => return Step::Refuse,
                    Head::Blank(count) => self.take(count, true),
                    Head::Request { length, body } => {
                        self.take(length, true);
                        self.phase = Phase::Http(body);
                    }
                },
                Phase::Http(Http::Body(left) | Http::Data(left)) => {
                    let count = usize::try_from(left).unwrap_or(usize::MAX).min(self.pending.len());
                    self.take(count, false);
                    let left = left - count as u64;
                    self.phase = Phase::Http(match (self.phase, left) {
                        (Phase::Http(Http::Body(_)), 0) => Http::Head,
                        (Phase::Http(Http::Body(_)), left) => Http::Body(left),
                        (_, 0) => Http::DataEnd { cr: false },
                        (_, left) => Http::Data(left),
                    });
                }
                Phase::Http(framing) => {
                    let Some(after) = chunk_framing(framing, self.pending[0]) else {
                        return Step::Refuse;
                    };
                    self.take(1, true);
                    self.phase = Phase::Http(after);
                }
            }
        }
    }

    /// Keeps the first `length` pending bytes as read; the rest of the stream passes unread.
    fn open(&mut self, length: usize) -> Step {
        self.take(length, true);
        self.pending.clear();
        self.phase = Phase::Open { from: self.next };
        Step::Pass
    }

    fn wait(&self, limit: usize) -> Step {
        if self.pending.len() > limit {
            Step::Refuse
        } else {
            Step::Hold
        }
    }

    /// Takes `count` decided bytes off the front of the pending ones, keeping them when a
    /// decision read them.
    fn take(&mut self, count: usize, keep: bool) {
        let at = self.next - self.pending.len() as u64;
        if !keep {
            self.pending.drain(..count);
            return;
        }
        let taken: Vec<u8> = self.pending.drain(..count).collect();
        self.kept_bytes += taken.len();
        match self.kept.back_mut() {
            Some((start, last)) if *start + last.len() as u64 == at && last.len() + taken.len() <= KEPT_PIECE => {
                last.extend_from_slice(&taken);
            }
            _ => self.kept.push_back((at, taken)),
        }
    }

    /// Forgets kept bytes the guest can no longer send again.
    fn prune(&mut self) {
        while let Some((at, bytes)) = self.kept.front() {
            if at + bytes.len() as u64 + HORIZON > self.next {
                break;
            }
            self.kept_bytes -= bytes.len();
            self.kept.pop_front();
        }
    }

    /// Refuses the connection: nothing more of it goes on. The reset to the user network
    /// is at the next byte it expects, the first one held back.
    fn refuse(&mut self, segment: &Segment<'_>) -> Verdict {
        let sequence = self.start.wrapping_add(self.released as u32);
        self.phase = Phase::Refused;
        self.closing = true;
        self.held = Vec::new();
        self.held_bytes = 0;
        self.pending = Vec::new();
        self.kept = VecDeque::new();
        self.kept_bytes = 0;
        Verdict::Reset {
            guest: reset_guest(segment),
            network: Some(reset_network(segment, sequence)),
        }
    }
}

/// The user network's answers (SYN-ACKs) to the guest's SYNs to addresses held by name, noted
/// by the thread that passes the user network's frames back before the guest can see them.
/// The user network keeps one connection per pair of ports and opens a new one, with a SYN-ACK
/// that acknowledges the new SYN, only when it has none: so an answer to exactly a
/// connection's SYN, noted after that SYN went on, proves the user network's connection is
/// that one, starting where the filter starts reading.
pub(super) struct Handshakes {
    addresses: HashSet<[u8; 4]>,
    answered: Mutex<HashMap<Key, Answer>>,
}

/// The user network's answer to one SYN: what it acknowledged, when it was noted and the
/// window it offered (`None` when it scales its window).
#[derive(Clone, Copy, Debug)]
struct Answer {
    acknowledged: u32,
    noted: Instant,
    window: Option<u16>,
}

impl std::fmt::Debug for Handshakes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Handshakes").field("addresses", &self.addresses.len()).finish_non_exhaustive()
    }
}

impl Handshakes {
    /// Notes the answers from `addresses` alone: those held by name.
    pub(super) fn new(addresses: HashSet<[u8; 4]>) -> Self {
        Self {
            addresses,
            answered: Mutex::new(HashMap::new()),
        }
    }

    /// Notes `frame`, one the user network sends the guest, `now`, when it is a SYN-ACK from
    /// an address held by name.
    pub(super) fn note(&self, frame: &[u8], now: Instant) {
        if self.addresses.is_empty()
            || frame.len() < 54
            || frame[12..14] != [0x08, 0x00]
            || frame[14] != 0x45
            || frame[23] != TCP
            || frame[47] & (SYN | ACK | RST) != SYN | ACK
        {
            return;
        }
        let (Ok(source), Ok(guest)) = (<[u8; 4]>::try_from(&frame[26..30]), <[u8; 4]>::try_from(&frame[30..34])) else {
            return;
        };
        if !self.addresses.contains(&source) {
            return;
        }
        let key = Key {
            source: guest,
            source_port: u16::from_be_bytes([frame[36], frame[37]]),
            destination: source,
            destination_port: u16::from_be_bytes([frame[34], frame[35]]),
        };
        let acknowledged = u32::from_be_bytes([frame[42], frame[43], frame[44], frame[45]]);
        // The window of a SYN-ACK is never scaled; a window-scale option scales the later
        // ones, and then the filter offers none of its own.
        let header = usize::from(frame[46] >> 4) * 4;
        let mut options = frame.get(54..34 + header).unwrap_or(&[]);
        let mut scaled = false;
        while let Some((&kind, rest)) = options.split_first() {
            match kind {
                0 => break,
                1 => options = rest,
                _ => {
                    let length = usize::from(rest.first().copied().unwrap_or(0));
                    scaled |= kind == 3;
                    if length < 2 || length > options.len() {
                        break;
                    }
                    options = &options[length..];
                }
            }
        }
        let window = (!scaled).then(|| u16::from_be_bytes([frame[48], frame[49]]));
        let Ok(mut answered) = self.answered.lock() else {
            return;
        };
        if answered.len() >= MAX_CONNECTIONS && !answered.contains_key(&key) {
            answered.retain(|_, answer| now.saturating_duration_since(answer.noted) < HANDSHAKE_IDLE);
            let oldest = answered.iter().min_by_key(|(_, answer)| answer.noted).map(|(key, _)| *key);
            if let (true, Some(oldest)) = (answered.len() >= MAX_CONNECTIONS, oldest) {
                answered.remove(&oldest);
            }
        }
        answered.insert(key, Answer { acknowledged, noted: now, window });
    }

    /// The user network's answer to `key`'s SYN that starts its stream at `start`, noted
    /// since `opened`, when that SYN came (the answer is then used up); `None` without one.
    fn answered(&self, key: Key, start: u32, opened: Instant) -> Option<Answer> {
        let Ok(mut answered) = self.answered.lock() else {
            return None;
        };
        match answered.get(&key) {
            Some(answer) if answer.acknowledged == start && answer.noted >= opened => answered.remove(&key),
            _ => None,
        }
    }
}

/// The connections of one VM to addresses held by name, with the site each may ask for.
pub(super) struct Connections {
    table: HashMap<Key, Connection>,
    handshakes: std::sync::Arc<Handshakes>,
    used: usize,
    swept: Option<Instant>,
}

impl std::fmt::Debug for Connections {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Connections")
            .field("followed", &self.table.len())
            .field("bytes", &self.used)
            .finish_non_exhaustive()
    }
}

impl Connections {
    pub(super) fn new(handshakes: std::sync::Arc<Handshakes>) -> Self {
        Self {
            table: HashMap::new(),
            handshakes,
            used: 0,
            swept: None,
        }
    }

    /// The fate of one TCP segment the guest sent to an address and port its targets admit
    /// by name alone, `now`. `may` says whether a site name may be asked for there.
    pub(super) fn judge(
        &mut self,
        frame: &[u8],
        packet: &Ipv4<'_>,
        now: Instant,
        may: &dyn Fn(&str) -> bool,
    ) -> Verdict {
        self.sweep(now);
        let Some(segment) = Segment::parse(frame, packet) else {
            return Verdict::Drop;
        };
        let key = segment.key;
        if segment.flags & SYN != 0 {
            // A new connection (or its SYN again): the handshake goes on, its bytes wait. (A
            // SYN the user network drops is never answered, so its connection's bytes are
            // refused: see `Handshakes`.)
            if segment.flags & (ACK | RST | FIN | URG) != 0 || !segment.payload.is_empty() {
                return Verdict::Drop;
            }
            let start = segment.sequence.wrapping_add(1);
            match self.table.get_mut(&key) {
                Some(known) if known.start == start => known.seen = now,
                _ => self.follow(key, Connection::new(start, now)),
            }
            return Verdict::Forward;
        }
        if segment.flags & RST != 0 {
            // The user network takes no bytes with a reset.
            if !segment.payload.is_empty() {
                return Verdict::Drop;
            }
            if let Some(ended) = self.table.remove(&key) {
                self.used -= ended.usage();
            }
            return Verdict::Forward;
        }
        let Some(connection) = self.table.get_mut(&key) else {
            // A connection never seen opening (or forgotten): its bytes never go on unread,
            // nor an urgent mark on bytes it may still hold.
            if segment.payload.is_empty() {
                return if segment.flags & URG == 0 { Verdict::Forward } else { Verdict::Drop };
            }
            return Verdict::Reset {
                guest: reset_guest(&segment),
                network: Some(reset_network(&segment, segment.sequence)),
            };
        };
        connection.seen = now;
        if connection.phase == Phase::Refused {
            return Verdict::Reset {
                guest: reset_guest(&segment),
                network: None,
            };
        }
        // The user network drops a segment without an acknowledgement, and one with a bad
        // checksum (a later copy carries its bytes); a bare acknowledgement carries nothing.
        let carries = !segment.payload.is_empty() || segment.flags & (FIN | URG) != 0;
        if segment.flags & ACK == 0 || (carries && !segment.checksums_hold()) {
            return Verdict::Drop;
        }
        if !connection.confirmed {
            if let Some(answer) = self.handshakes.answered(key, connection.start, connection.opened) {
                connection.confirmed = true;
                connection.window = answer.window;
            }
        }
        let before = connection.usage();
        let outcome = if connection.confirmed || segment.payload.is_empty() {
            connection.segment(&segment, may)
        } else {
            // Bytes for a connection the user network never opened for this SYN.
            Outcome::Refuse
        };
        let after = connection.usage();
        self.used = self.used - before + after;
        let outcome = if after > before && self.used > BUDGET {
            Outcome::Refuse
        } else {
            outcome
        };
        match outcome {
            Outcome::Forward => Verdict::Forward,
            Outcome::Drop => Verdict::Drop,
            Outcome::Answer(frame) => Verdict::Answer(frame),
            Outcome::Held(acknowledgement) => Verdict::Held(acknowledgement),
            Outcome::Release(frames) => Verdict::Release(frames),
            Outcome::Refuse => {
                let usage = connection.usage();
                let verdict = connection.refuse(&segment);
                self.used -= usage;
                verdict
            }
        }
    }

    /// Follows a new connection, in place of any earlier one on the same ports; with too
    /// many followed, the least recently used is forgotten (a closed one first).
    fn follow(&mut self, key: Key, connection: Connection) {
        if let Some(earlier) = self.table.remove(&key) {
            self.used -= earlier.usage();
        }
        if self.table.len() >= MAX_CONNECTIONS {
            let oldest = self
                .table
                .iter()
                .min_by_key(|(_, known)| (!known.closing, known.seen))
                .map(|(key, _)| *key);
            if let Some(oldest) = oldest.and_then(|oldest| self.table.remove(&oldest)) {
                self.used -= oldest.usage();
            }
        }
        self.table.insert(key, connection);
    }

    /// Forgets connections quiet for longer than they are remembered.
    fn sweep(&mut self, now: Instant) {
        if self.swept.is_some_and(|swept| now.saturating_duration_since(swept) < SWEEP) {
            return;
        }
        self.swept = Some(now);
        let used = &mut self.used;
        self.table.retain(|_, connection| {
            let limit = if connection.closing { CLOSED_IDLE } else { IDLE };
            let remembered = now.saturating_duration_since(connection.seen) < limit;
            if !remembered {
                *used -= connection.usage();
            }
            remembered
        });
    }

    #[cfg(test)]
    fn followed(&self) -> usize {
        self.table.len()
    }
}

/// What a connection's first bytes are.
#[derive(Debug, PartialEq, Eq)]
enum Opening {
    Need,
    Refuse,
    /// A TLS ClientHello, in records making up `length` bytes, and the name it asks for.
    Tls { length: usize, name: Option<String> },
    /// An HTTP request: read as such from the start.
    Http,
    /// Another protocol, told by its first `length` bytes.
    Other { length: usize },
}

fn opening(bytes: &[u8]) -> Opening {
    let blanks = bytes.iter().take_while(|byte| blank(**byte)).count();
    let rest = &bytes[blanks..];
    let Some(&first) = rest.first() else {
        return if bytes.len() > MAX_LINE { Opening::Refuse } else { Opening::Need };
    };
    if first == 0x16 {
        // TLS starts with its first byte; a server would not skip blanks before it.
        if blanks > 0 {
            return Opening::Refuse;
        }
        return match client_hello(rest) {
            Hello::Need => Opening::Need,
            Hello::Refuse => Opening::Refuse,
            Hello::Found { length, name } => Opening::Tls { length, name },
        };
    }
    if first & 0x80 != 0 {
        // SSL 2's ClientHello (a two-byte record header, then message type 1) carries no
        // extensions, so no name. Anything else is read as a line, like text.
        match rest.get(2) {
            None => return Opening::Need,
            Some(1) => return Opening::Refuse,
            Some(_) => {}
        }
    }
    for (index, &byte) in rest.iter().enumerate().take(MAX_LINE) {
        match byte {
            b'\n' => {
                return if http_like(&rest[..index]) {
                    Opening::Http
                } else {
                    Opening::Other {
                        length: blanks + index + 1,
                    }
                };
            }
            b'\t' | 0x0b | 0x0c | b'\r' | 0x20..=0x7e | 0x80..=0xff => {}
            // A control character: no request line has one, whatever a server forgives.
            _ => {
                return Opening::Other {
                    length: blanks + index + 1,
                }
            }
        }
    }
    if rest.len() >= MAX_LINE {
        Opening::Refuse
    } else {
        Opening::Need
    }
}

/// Whether a first line is, or could be taken by a forgiving server as, an HTTP request
/// line: it names an HTTP version, CONNECTs, or has a token and then a request target
/// (a path, `*` or an absolute address) after whitespace.
fn http_like(line: &[u8]) -> bool {
    let lower = line.to_ascii_lowercase();
    if lower.windows(5).any(|window| window == b"http/") {
        return true;
    }
    let mut words = line
        .split(|byte| matches!(byte, b' ' | b'\t' | 0x0b | 0x0c | b'\r'))
        .filter(|word| !word.is_empty());
    let Some(method) = words.next() else {
        return false;
    };
    if method.eq_ignore_ascii_case(b"connect") {
        return true;
    }
    let Some(target) = words.next() else {
        return false;
    };
    method.iter().all(|byte| tchar(*byte))
        && (target[0] == b'/' || target == b"*" || target.windows(3).any(|window| window == b"://"))
}

/// A TLS ClientHello read from its records.
#[derive(Debug, PartialEq, Eq)]
enum Hello {
    Need,
    Refuse,
    Found { length: usize, name: Option<String> },
}

fn client_hello(bytes: &[u8]) -> Hello {
    let mut handshake = Vec::new();
    let mut at = 0;
    loop {
        let Some(header) = bytes.get(at..at + 5) else {
            return Hello::Need;
        };
        // Handshake records of SSL 3.0 to TLS 1.3, each 1 to 2^14 bytes.
        let size = usize::from(u16::from_be_bytes([header[3], header[4]]));
        if header[0] != 0x16 || header[1] != 3 || header[2] > 4 || !(1..=16384).contains(&size) {
            return Hello::Refuse;
        }
        let Some(fragment) = bytes.get(at + 5..at + 5 + size) else {
            return Hello::Need;
        };
        handshake.extend_from_slice(fragment);
        at += 5 + size;
        if handshake.len() < 4 {
            continue;
        }
        let body = usize::try_from(u32::from_be_bytes([0, handshake[1], handshake[2], handshake[3]])).unwrap_or(usize::MAX);
        if handshake[0] != 1 || body > MAX_OPENING {
            return Hello::Refuse;
        }
        match handshake.len().cmp(&(4 + body)) {
            std::cmp::Ordering::Less => continue,
            // Only the ClientHello comes in these records.
            std::cmp::Ordering::Greater => return Hello::Refuse,
            std::cmp::Ordering::Equal => {
                return match server_name(&handshake[4..]) {
                    Some(name) => Hello::Found { length: at, name },
                    None => Hello::Refuse,
                };
            }
        }
    }
}

/// Reads a message front to back.
struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, count: usize) -> Option<&'a [u8]> {
        let taken = self.0.get(..count)?;
        self.0 = &self.0[count..];
        Some(taken)
    }

    fn byte(&mut self) -> Option<u8> {
        self.take(1).map(|bytes| bytes[0])
    }

    fn short(&mut self) -> Option<usize> {
        self.take(2).map(|bytes| usize::from(u16::from_be_bytes([bytes[0], bytes[1]])))
    }
}

/// The server name a ClientHello's body asks for (`Some(None)`: none), or `None` when it is
/// malformed: one server_name extension at most, holding one host name.
fn server_name(hello: &[u8]) -> Option<Option<String>> {
    let mut reader = Reader(hello);
    if reader.short()? < 0x0300 {
        return None;
    }
    reader.take(32)?;
    let session = usize::from(reader.byte()?);
    if session > 32 {
        return None;
    }
    reader.take(session)?;
    let suites = reader.short()?;
    if suites < 2 || suites % 2 != 0 {
        return None;
    }
    reader.take(suites)?;
    let methods = usize::from(reader.byte()?);
    if methods == 0 {
        return None;
    }
    reader.take(methods)?;
    if reader.0.is_empty() {
        return Some(None);
    }
    if reader.short()? != reader.0.len() {
        return None;
    }
    let mut seen: Vec<usize> = Vec::new();
    let mut name = None;
    while !reader.0.is_empty() {
        let kind = reader.short()?;
        let size = reader.short()?;
        let data = reader.take(size)?;
        // A repeated extension: servers differ on which one counts.
        if seen.contains(&kind) {
            return None;
        }
        seen.push(kind);
        if kind == 0 {
            let mut list = Reader(data);
            if list.short()? != list.0.len() || list.byte()? != 0 {
                return None;
            }
            let size = list.short()?;
            let host = list.take(size)?;
            if !list.0.is_empty() {
                return None;
            }
            name = Some(host_name(host)?);
        }
    }
    Some(name)
}

/// A DNS host name as a connection gives it, lowercase and without its final dot; `None`
/// for anything else (an IPv6 literal, a user name, other characters).
fn host_name(bytes: &[u8]) -> Option<String> {
    let bytes = bytes.strip_suffix(b".").unwrap_or(bytes);
    if !(1..=253).contains(&bytes.len())
        || !bytes.iter().all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.'))
    {
        return None;
    }
    Some(String::from_utf8_lossy(bytes).to_ascii_lowercase())
}

/// What the front of a plain HTTP connection's pending bytes is.
#[derive(Debug, PartialEq, Eq)]
enum Head {
    Need,
    Refuse,
    /// Blank bytes before the next request line.
    Blank(usize),
    /// A request head of `length` bytes that may go on, and what follows it.
    Request { length: usize, body: Http },
}

fn request_head(bytes: &[u8], may: &dyn Fn(&str) -> bool) -> Head {
    let blanks = bytes.iter().take_while(|byte| blank(**byte)).count();
    if blanks > 0 {
        return Head::Blank(blanks);
    }
    // The head ends at its first empty line; every line ends with CR LF.
    let mut end = None;
    for (index, &byte) in bytes.iter().enumerate().take(MAX_HEAD) {
        match byte {
            b'\n' if index == 0 || bytes[index - 1] != b'\r' => return Head::Refuse,
            b'\n' if index >= 3 && bytes[index - 3..index] == *b"\r\n\r" => {
                end = Some(index + 1);
                break;
            }
            b'\r' if bytes.get(index + 1).is_some_and(|after| *after != b'\n') => return Head::Refuse,
            _ => {}
        }
    }
    let Some(end) = end else {
        return if bytes.len() >= MAX_HEAD { Head::Refuse } else { Head::Need };
    };
    match request(&bytes[..end - 4], may) {
        Some(body) => Head::Request { length: end, body },
        None => Head::Refuse,
    }
}

/// Checks one request head (without its final empty line): `Some` with what follows it when
/// it may go on.
fn request(head: &[u8], may: &dyn Fn(&str) -> bool) -> Option<Http> {
    let mut lines = CrLfLines(head);
    let line = lines.next()?;
    let mut parts = line.split(|byte| *byte == b' ');
    let (method, target, version) = (parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some()
        || !(1..=20).contains(&method.len())
        || !method.iter().all(|byte| byte.is_ascii_uppercase() || matches!(byte, b'-' | b'_'))
        || matches!(method, b"CONNECT" | b"PRI")
        || target.is_empty()
        || !target.iter().all(|byte| (0x21..=0x7e).contains(byte))
    {
        return None;
    }
    let http11 = match version {
        b"HTTP/1.1" => true,
        b"HTTP/1.0" => false,
        _ => return None,
    };
    let lower = target.to_ascii_lowercase();
    let address = ["http://", "https://"]
        .iter()
        .find_map(|scheme| lower.strip_prefix(scheme.as_bytes()));
    let named_by_target = match address {
        Some(rest) => {
            let authority = rest.split(|byte| matches!(byte, b'/' | b'?' | b'#')).next().unwrap_or(&[]);
            Some(authority_host(authority).flatten()?)
        }
        None if target == b"*" => (method == b"OPTIONS").then_some(None)?,
        None if target[0] == b'/' => None,
        None => return None,
    };
    let (mut host, mut length, mut encoding, mut upgrade) = (Vec::new(), Vec::new(), Vec::new(), false);
    for line in lines {
        let colon = line.iter().position(|byte| *byte == b':')?;
        let (name, value) = (&line[..colon], &line[colon + 1..]);
        // A name of token characters alone: no folding, no space before the colon.
        if name.is_empty() || !name.iter().all(|byte| tchar(*byte)) {
            return None;
        }
        let value = trim(value);
        if !value.iter().all(|byte| matches!(byte, b'\t' | 0x20..=0x7e | 0x80..=0xff)) {
            return None;
        }
        match name.to_ascii_lowercase().as_slice() {
            b"host" => host.push(value),
            b"content-length" => length.push(value),
            b"transfer-encoding" => encoding.push(value),
            b"upgrade" => upgrade = true,
            _ => {}
        }
    }
    if host.len() > 1 || length.len() > 1 || encoding.len() > 1 || upgrade {
        return None;
    }
    let named_by_host = match host.first() {
        Some(value) => authority_host(value)?,
        None => None,
    };
    let named = match (named_by_target, named_by_host) {
        (Some(target), Some(host)) if target != host => return None,
        (Some(name), _) | (None, Some(name)) => Some(name),
        (None, None) => None,
    };
    if named.is_some_and(|name| !may(&name)) {
        return None;
    }
    match (encoding.first(), length.first()) {
        (Some(_), Some(_)) => None,
        (Some(coding), None) => (http11 && coding.eq_ignore_ascii_case(b"chunked")).then_some(Http::Size {
            digits: 0,
            value: 0,
            cr: false,
        }),
        (None, Some(value)) => {
            if !(1..=18).contains(&value.len()) || !value.iter().all(u8::is_ascii_digit) {
                return None;
            }
            let size: u64 = std::str::from_utf8(value).ok()?.parse().ok()?;
            Some(if size == 0 { Http::Head } else { Http::Body(size) })
        }
        (None, None) => Some(Http::Head),
    }
}

/// The host an authority (`host[:port]`) names: `Some(None)` when empty, `None` when it is
/// no plain host name with an optional port.
fn authority_host(authority: &[u8]) -> Option<Option<String>> {
    if authority.is_empty() {
        return Some(None);
    }
    let (host, port) = match authority.iter().rposition(|byte| *byte == b':') {
        Some(colon) => (&authority[..colon], Some(&authority[colon + 1..])),
        None => (authority, None),
    };
    if port.is_some_and(|port| !(1..=5).contains(&port.len()) || !port.iter().all(u8::is_ascii_digit)) {
        return None;
    }
    host_name(host).map(Some)
}

fn trim(value: &[u8]) -> &[u8] {
    let start = value.iter().position(|byte| !matches!(byte, b' ' | b'\t')).unwrap_or(value.len());
    let end = value.iter().rposition(|byte| !matches!(byte, b' ' | b'\t')).map_or(start, |last| last + 1);
    &value[start..end]
}

/// The lines of a head, split at CR LF (bare CRs and LFs were refused before).
struct CrLfLines<'a>(&'a [u8]);

impl<'a> Iterator for CrLfLines<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<&'a [u8]> {
        if self.0.is_empty() {
            return None;
        }
        match self.0.windows(2).position(|pair| pair == b"\r\n") {
            Some(end) => {
                let line = &self.0[..end];
                self.0 = &self.0[end + 2..];
                Some(line)
            }
            None => {
                let line = self.0;
                self.0 = &[];
                Some(line)
            }
        }
    }
}

/// The state after one framing byte of a chunked body; `None` for a byte the strict framing
/// refuses (chunk extensions, trailers, whitespace, a size of 16 digits or more).
fn chunk_framing(state: Http, byte: u8) -> Option<Http> {
    match state {
        Http::Size { digits, value, cr: false } => match byte {
            b'\r' if digits > 0 => Some(Http::Size { digits, value, cr: true }),
            _ if digits < 15 => {
                let digit = char::from(byte).to_digit(16)?;
                Some(Http::Size {
                    digits: digits + 1,
                    value: value * 16 + u64::from(digit),
                    cr: false,
                })
            }
            _ => None,
        },
        Http::Size { value, cr: true, .. } => (byte == b'\n').then_some(if value == 0 {
            Http::Last { cr: false }
        } else {
            Http::Data(value)
        }),
        Http::DataEnd { cr: false } => (byte == b'\r').then_some(Http::DataEnd { cr: true }),
        Http::DataEnd { cr: true } => (byte == b'\n').then_some(Http::Size {
            digits: 0,
            value: 0,
            cr: false,
        }),
        Http::Last { cr: false } => (byte == b'\r').then_some(Http::Last { cr: true }),
        Http::Last { cr: true } => (byte == b'\n').then_some(Http::Head),
        Http::Head | Http::Body(_) | Http::Data(_) => None,
    }
}

#[cfg(test)]
#[path = "network_names_tests.rs"]
mod tests;
