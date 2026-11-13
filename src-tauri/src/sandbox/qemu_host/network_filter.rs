//! The host's filter of a Sandbox VM's network card. A profile with a card sends every frame
//! of QEMU's user network through two filter redirectors (`sandbox::qemu` profile): the
//! guest's frames come out on the private directory's socket 0 and go on to the user network
//! only when written back on socket 1; the user network's frames come out on socket 2 and
//! reach the guest only when written back on socket 3. A redirector with an output keeps
//! every frame it takes, so nothing passes while this filter is not connected or after it
//! stopped: the card then reaches nothing. The guest cannot change any of this: its routes,
//! its firewall and its resolver are all inside the VM.
//!
//! What the guest may send on ([`Policy`]):
//!
//! - ARP, and DHCP to the user network's own server, which never leave QEMU.
//! - **The public internet** (a card without targets): TCP, UDP and ICMP to public IPv4
//!   addresses, and DNS to the user network's resolver (10.0.2.3), which asks this
//!   computer's resolvers. Never this computer: not the user network's gateway or its other
//!   addresses (QEMU turns them into this computer's loopback), not an address this computer
//!   holds now, and not loopback, link-local, cloud management, private, shared, reserved
//!   (benchmarking, documentation, the old 6to4 relay) or multicast space, so no service of
//!   this computer and nothing on its networks.
//! - **Targets** (a launch that named them): TCP to the named addresses and ports alone.
//!   The guest's DNS questions never leave: the filter answers them itself, with the
//!   addresses this computer resolved at launch for a named host and "no such name" for
//!   every other. An address this computer holds now is refused even if it was named. A
//!   host named by its name may share its addresses with other sites (a CDN, shared
//!   hosting), so on an address the person did not name itself every connection must ask
//!   for a named host there by name, as HTTPS (its ClientHello's server name) and HTTP
//!   (each request's Host) do, or be another protocol, which names no site (`names`).
//!
//! A refused TCP connection or UDP datagram is answered at once with ICMP "communication
//! administratively prohibited", so a program in the VM fails fast ("No route to host")
//! instead of waiting, and a connection refused for the site it asked for is reset;
//! anything else refused is dropped. The user network's own frames to the guest are its
//! answers to what was let through, and pass unchanged. Frames carry no IPv6 (the user
//! network has none) and no IPv4 options or fragments: those are dropped.
//!
//! QEMU waits in its main loop until the host has read each frame it sends, and the same
//! loop reads the frames the host sends it, so the host reads QEMU's frames all the time and
//! never waits for a send before reading on ([`Outbox`]).

use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
use std::io::{ErrorKind, Read, Write};
use std::net::Ipv4Addr;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use super::socket::{connect, Direction, SocketTimeouts, UnixStream};
use crate::sandbox::backend::NetworkTarget;
use crate::sandbox::qemu::{HostPath, QemuLaunchPlan};
use crate::security::network::{cloud_management_peer, private_peer};

#[path = "network_names.rs"]
mod names;

use names::{Connections, Handshakes};

/// The user network's addresses: the guest's subnet, its gateway (which QEMU maps to this
/// computer's loopback) and its resolver.
const GUEST_NETWORK: [u8; 3] = [10, 0, 2];
const GATEWAY: [u8; 4] = [10, 0, 2, 2];
const RESOLVER: [u8; 4] = [10, 0, 2, 3];
const BROADCAST: [u8; 4] = [255, 255, 255, 255];

const ETHERTYPE_IPV4: u16 = 0x0800;
const ETHERTYPE_ARP: u16 = 0x0806;
const ICMP: u8 = 1;
const TCP: u8 = 6;
const UDP: u8 = 17;
const DNS_PORT: u16 = 53;

/// Smallest and largest frame either side may send (an Ethernet header; QEMU's own bound).
pub const MIN_FRAME_BYTES: usize = 14;
pub const MAX_FRAME_BYTES: usize = 65536;
/// How long this computer's address list is trusted before it is read again (when a frame
/// would go to an address outside the user network), and how soon a failed read is retried;
/// meanwhile such frames are refused.
const ADDRESS_LEASE: Duration = Duration::from_secs(1);
const ADDRESS_RETRY: Duration = Duration::from_millis(250);
/// How long the answers for a named host are cached in the guest. The answers never change
/// while the VM runs.
const DNS_TTL_SECONDS: u32 = 300;
/// The classic DNS message limit over UDP; an answer stays within it.
const DNS_UDP_BYTES: usize = 512;
/// How long a thread waits before it looks at the stop flag again, and the most a frame may
/// wait for QEMU to take it (QEMU reads all the time; one that took nothing for so long is
/// stuck, and the card stops).
const POLL: Duration = Duration::from_millis(200);
const WRITE_DEADLINE: Duration = Duration::from_secs(30);
/// Most bytes of frames waiting for one side ([`Outbox`]), and how far frames a held
/// connection releases may go past that.
const OUTBOX_BYTES: usize = 4 << 20;
const RELEASED_BYTES: usize = 2 * OUTBOX_BYTES;
/// How long the host keeps trying the sockets QEMU serves (they exist once QMP answers).
const CONNECT_WINDOW: Duration = Duration::from_secs(5);

/// What a VM's network card may reach.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Reach {
    /// The public internet: never this computer or its networks.
    PublicInternet,
    /// These targets alone.
    Targets(Vec<NetworkTarget>),
}

impl Reach {
    /// What `plan`'s card may reach; `None` for a profile without a card.
    pub fn of(plan: &QemuLaunchPlan) -> Option<Self> {
        plan.profile().internet().then(|| match plan.targets() {
            Some(targets) => Self::Targets(targets.to_vec()),
            None => Self::PublicInternet,
        })
    }
}

/// What becomes of one frame the guest sent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// On to the user network.
    Forward,
    Drop,
    /// Kept from the user network; this frame goes back to the guest instead.
    Answer(Vec<u8>),
    /// Kept by the filter until its connection says which site it is for: it goes on with
    /// a later frame ([`Verdict::Release`]) or never. While a connection's opening is held,
    /// the guest gets an acknowledgement of it, so it sends the rest.
    Held(Option<Vec<u8>>),
    /// These frames go on to the user network, in order: those held, then this one. They
    /// are never dropped for congestion: the guest may have been told they arrived.
    Release(Vec<Vec<u8>>),
    /// A connection refused: these resets go back to the guest and, when the user network
    /// may have opened the connection, on to it (which closes its connection to the server).
    Reset { guest: Vec<u8>, network: Option<Vec<u8>> },
}

/// The ports of one target address.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Ports {
    Every,
    Only(BTreeSet<u16>),
}

impl Ports {
    fn allows(&self, port: u16) -> bool {
        match self {
            Self::Every => true,
            Self::Only(ports) => ports.contains(&port),
        }
    }

    /// These ports and `more` (none: every port).
    fn add(&mut self, more: &[u16]) {
        match self {
            Self::Every => {}
            Self::Only(_) if more.is_empty() => *self = Self::Every,
            Self::Only(ports) => ports.extend(more),
        }
    }
}

#[derive(Debug)]
enum Mode {
    Public,
    Targets {
        /// The addresses named themselves, and their ports: any connection there may go on.
        addresses: HashMap<[u8; 4], Ports>,
        /// The addresses of hosts named by name, with each such host and its ports: a
        /// connection there must ask for one of those hosts (`names`).
        hosts: HashMap<[u8; 4], Vec<(String, Ports)>>,
        /// The DNS answers: each named host's addresses.
        names: HashMap<String, Vec<[u8; 4]>>,
    },
}

/// How a TCP connection to an address and port of the targets may go on.
enum Admission {
    No,
    /// Whatever it asks for: the address was named itself.
    Address,
    /// Only asking for a host named by name there.
    Names,
}

/// The decisions of one VM's filter (module notes), with this computer's addresses as last
/// read and the connections it reads for the site they ask for.
#[derive(Debug)]
pub struct Policy {
    mode: Mode,
    host: HashSet<[u8; 4]>,
    checked: Option<Instant>,
    failed: Option<Instant>,
    connections: Connections,
    handshakes: Arc<Handshakes>,
}

impl Policy {
    pub fn new(reach: &Reach) -> Self {
        let mode = match reach {
            Reach::PublicInternet => Mode::Public,
            Reach::Targets(targets) => {
                let mut addresses: HashMap<[u8; 4], Ports> = HashMap::new();
                let mut hosts: HashMap<[u8; 4], Vec<(String, Ports)>> = HashMap::new();
                let mut names: HashMap<String, Vec<[u8; 4]>> = HashMap::new();
                for target in targets {
                    if target.host.parse::<Ipv4Addr>().is_ok() {
                        for address in &target.addresses {
                            addresses
                                .entry(address.octets())
                                .or_insert_with(|| Ports::Only(BTreeSet::new()))
                                .add(&target.ports);
                        }
                        continue;
                    }
                    let name = target.host.trim_end_matches('.').to_ascii_lowercase();
                    let known = names.entry(name.clone()).or_default();
                    for address in &target.addresses {
                        if !known.contains(&address.octets()) {
                            known.push(address.octets());
                        }
                        let named = hosts.entry(address.octets()).or_default();
                        match named.iter_mut().find(|(host, _)| *host == name) {
                            Some((_, ports)) => ports.add(&target.ports),
                            None => {
                                let mut ports = Ports::Only(BTreeSet::new());
                                ports.add(&target.ports);
                                named.push((name.clone(), ports));
                            }
                        }
                    }
                }
                Mode::Targets { addresses, hosts, names }
            }
        };
        let held_by_name = match &mode {
            Mode::Targets { hosts, .. } => hosts.keys().copied().collect(),
            Mode::Public => HashSet::new(),
        };
        let handshakes = Arc::new(Handshakes::new(held_by_name));
        Self {
            mode,
            host: HashSet::new(),
            checked: None,
            failed: None,
            connections: Connections::new(Arc::clone(&handshakes)),
            handshakes,
        }
    }

    /// Where the user network's answers to the guest's SYNs are noted (`pass_back`).
    fn handshakes(&self) -> Arc<Handshakes> {
        Arc::clone(&self.handshakes)
    }

    /// How a TCP connection to `address` on `port` may go on.
    fn admits(&self, address: [u8; 4], port: u16) -> Admission {
        let Mode::Targets { addresses, hosts, .. } = &self.mode else {
            return Admission::No;
        };
        if addresses.get(&address).is_some_and(|ports| ports.allows(port)) {
            Admission::Address
        } else if hosts
            .get(&address)
            .is_some_and(|named| named.iter().any(|(_, ports)| ports.allows(port)))
        {
            Admission::Names
        } else {
            Admission::No
        }
    }

    /// The fate of one frame the guest sent, `now`; `addresses` reads this computer's IPv4
    /// addresses when the last reading is older than its lease.
    pub fn from_guest(
        &mut self,
        frame: &[u8],
        now: Instant,
        addresses: &mut dyn FnMut() -> Result<HashSet<[u8; 4]>, String>,
    ) -> Verdict {
        if !(MIN_FRAME_BYTES..=MAX_FRAME_BYTES).contains(&frame.len()) {
            return Verdict::Drop;
        }
        match u16::from_be_bytes([frame[12], frame[13]]) {
            // ARP carries nothing routable; the guest needs it for the gateway and resolver.
            ETHERTYPE_ARP if frame.len() >= 42 && frame[14..20] == [0, 1, 8, 0, 6, 4] => {
                Verdict::Forward
            }
            ETHERTYPE_IPV4 => self.ipv4(frame, now, addresses),
            _ => Verdict::Drop,
        }
    }

    fn ipv4(
        &mut self,
        frame: &[u8],
        now: Instant,
        addresses: &mut dyn FnMut() -> Result<HashSet<[u8; 4]>, String>,
    ) -> Verdict {
        let Some(packet) = Ipv4::parse(frame) else {
            return Verdict::Drop;
        };
        let dhcp = packet.protocol == UDP && packet.ports() == Some((68, 67));
        // Only DHCP may come before the guest has an address.
        if packet.source == [0; 4] {
            return if dhcp && packet.destination == BROADCAST {
                Verdict::Forward
            } else {
                Verdict::Drop
            };
        }
        if packet.source[..3] != GUEST_NETWORK || !(4..=254).contains(&packet.source[3]) {
            return Verdict::Drop;
        }
        if dhcp && (packet.destination == GATEWAY || packet.destination == BROADCAST) {
            return Verdict::Forward;
        }
        if packet.destination == RESOLVER
            && matches!(packet.protocol, TCP | UDP)
            && packet.ports().is_some_and(|(_, port)| port == DNS_PORT)
        {
            return match &self.mode {
                Mode::Public => Verdict::Forward,
                Mode::Targets { names, .. } if packet.protocol == UDP => {
                    match dns_answer(frame, &packet, names) {
                        Some(answer) => Verdict::Answer(answer),
                        None => Verdict::Drop,
                    }
                }
                Mode::Targets { .. } => refuse(frame, &packet),
            };
        }
        if packet.destination[..3] == GUEST_NETWORK {
            // QEMU turns every other address of the user network into this computer's
            // loopback. A ping of the gateway is answered by QEMU itself.
            let ping = packet.protocol == ICMP && packet.transport.first() == Some(&8);
            if matches!(self.mode, Mode::Public) && packet.destination == GATEWAY && ping {
                return Verdict::Forward;
            }
            return refuse(frame, &packet);
        }
        let admission = match &self.mode {
            Mode::Public => {
                let allowed = public(packet.destination)
                    && match packet.protocol {
                        TCP | UDP => packet.ports().is_some(),
                        ICMP => packet.transport.len() >= 8,
                        _ => false,
                    };
                if allowed {
                    Admission::Address
                } else {
                    Admission::No
                }
            }
            Mode::Targets { .. } => match packet.ports() {
                Some((_, port)) if packet.protocol == TCP => self.admits(packet.destination, port),
                _ => Admission::No,
            },
        };
        if matches!(admission, Admission::No) || !self.elsewhere(packet.destination, now, addresses) {
            return refuse(frame, &packet);
        }
        match admission {
            Admission::Names => {
                let Mode::Targets { hosts, .. } = &self.mode else {
                    return Verdict::Drop;
                };
                let named = hosts.get(&packet.destination);
                let port = packet.ports().map_or(0, |(_, port)| port);
                let may = |name: &str| {
                    named.is_some_and(|named| named.iter().any(|(host, ports)| host == name && ports.allows(port)))
                };
                self.connections.judge(frame, &packet, now, &may)
            }
            _ => Verdict::Forward,
        }
    }

    /// Whether `address` is not this computer's, by a reading at most a lease old; a
    /// reading that fails refuses it.
    fn elsewhere(
        &mut self,
        address: [u8; 4],
        now: Instant,
        addresses: &mut dyn FnMut() -> Result<HashSet<[u8; 4]>, String>,
    ) -> bool {
        let fresh = self
            .checked
            .is_some_and(|checked| now.saturating_duration_since(checked) < ADDRESS_LEASE);
        if !fresh {
            if self
                .failed
                .is_some_and(|failed| now.saturating_duration_since(failed) < ADDRESS_RETRY)
            {
                return false;
            }
            match addresses() {
                Ok(read) if !read.is_empty() => {
                    self.host = read;
                    self.checked = Some(now);
                    self.failed = None;
                }
                _ => {
                    self.checked = None;
                    self.failed = Some(now);
                    return false;
                }
            }
        }
        !self.host.contains(&address)
    }
}

/// A public IPv4 address: not this computer's loopback or "this network", not link-local or
/// a cloud's management service, not private, shared or reserved space, not multicast or
/// broadcast.
fn public(address: [u8; 4]) -> bool {
    address[0] != 0
        && address[0] != 127
        && address[0] < 224
        && !cloud_management_peer(address)
        && !private_peer(address)
        && !reserved(address)
}

/// IANA special-purpose IPv4 space that is not globally reachable, beyond the private and
/// shared space: benchmarking (198.18.0.0/15, which labs and some VPNs route), the three
/// documentation networks and the deprecated 6to4 relay anycast (192.88.99.0/24).
pub(crate) fn reserved(address: [u8; 4]) -> bool {
    (address[0] == 198 && address[1] & 0xfe == 18)
        || address[..3] == [192, 0, 2]
        || address[..3] == [198, 51, 100]
        || address[..3] == [203, 0, 113]
        || address[..3] == [192, 88, 99]
}

/// A refused frame: a new TCP connection or a UDP datagram is answered "administratively
/// prohibited" at once; anything else is dropped.
fn refuse(frame: &[u8], packet: &Ipv4<'_>) -> Verdict {
    let syn = packet.protocol == TCP && packet.ports().is_some() && packet.transport[13] & 0x12 == 0x02;
    let datagram = packet.protocol == UDP && packet.ports().is_some();
    if syn || datagram {
        Verdict::Answer(prohibited(frame, packet))
    } else {
        Verdict::Drop
    }
}

/// An IPv4 packet without options or fragments, as a frame carries it.
struct Ipv4<'a> {
    source: [u8; 4],
    destination: [u8; 4],
    protocol: u8,
    transport: &'a [u8],
}

impl<'a> Ipv4<'a> {
    fn parse(frame: &'a [u8]) -> Option<Self> {
        // Version 4 with the 20-byte header: options are refused.
        if frame.len() < 34 || frame[14] != 0x45 {
            return None;
        }
        let total = usize::from(u16::from_be_bytes([frame[16], frame[17]]));
        if total < 20 || frame.len() < 14 + total {
            return None;
        }
        // No fragment: neither "more fragments" nor an offset.
        if u16::from_be_bytes([frame[20], frame[21]]) & 0x3fff != 0 {
            return None;
        }
        Some(Self {
            source: frame[26..30].try_into().ok()?,
            destination: frame[30..34].try_into().ok()?,
            protocol: frame[23],
            transport: &frame[34..14 + total],
        })
    }

    /// The source and destination ports of a well-formed TCP segment or UDP datagram.
    fn ports(&self) -> Option<(u16, u16)> {
        let transport = self.transport;
        let ports = || {
            (
                u16::from_be_bytes([transport[0], transport[1]]),
                u16::from_be_bytes([transport[2], transport[3]]),
            )
        };
        match self.protocol {
            TCP if transport.len() >= 20 => {
                let header = usize::from(transport[12] >> 4) * 4;
                (20..=transport.len()).contains(&header).then(ports)
            }
            UDP if transport.len() >= 8 => {
                let length = usize::from(u16::from_be_bytes([transport[4], transport[5]]));
                (8..=transport.len()).contains(&length).then(ports)
            }
            _ => None,
        }
    }
}

/// The one's-complement sum of `parts`, folded: the Internet checksum. The parts are summed
/// as one run of bytes (a part may end on an odd byte).
fn checksum(parts: &[&[u8]]) -> u16 {
    let mut sum: u64 = 0;
    let mut odd: Option<u8> = None;
    for part in parts {
        let mut bytes = *part;
        if let Some(high) = odd.take() {
            match bytes.split_first() {
                Some((&low, rest)) => {
                    sum += u64::from(u16::from_be_bytes([high, low]));
                    bytes = rest;
                }
                None => {
                    odd = Some(high);
                    continue;
                }
            }
        }
        let mut pairs = bytes.chunks_exact(2);
        for pair in &mut pairs {
            sum += u64::from(u16::from_be_bytes([pair[0], pair[1]]));
        }
        if let [last] = pairs.remainder() {
            odd = Some(*last);
        }
    }
    if let Some(high) = odd {
        sum += u64::from(u16::from_be_bytes([high, 0]));
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// A frame back to the guest that sent `request`: to its MAC from the MAC it addressed, an
/// IPv4 packet from `source` to `destination` carrying `transport`.
fn frame_to_guest(
    request: &[u8],
    source: [u8; 4],
    destination: [u8; 4],
    protocol: u8,
    transport: &[u8],
) -> Vec<u8> {
    let mut macs = [0u8; 12];
    macs[..6].copy_from_slice(&request[6..12]);
    macs[6..].copy_from_slice(&request[0..6]);
    ipv4_frame(&macs, source, destination, protocol, transport)
}

/// A frame on to the user network as if the guest that sent `request` sent it: between the
/// same MACs, an IPv4 packet from `source` to `destination` carrying `transport`.
fn frame_onward(
    request: &[u8],
    source: [u8; 4],
    destination: [u8; 4],
    protocol: u8,
    transport: &[u8],
) -> Vec<u8> {
    let mut macs = [0u8; 12];
    macs.copy_from_slice(&request[0..12]);
    ipv4_frame(&macs, source, destination, protocol, transport)
}

/// An Ethernet frame between `macs` (destination, then source) carrying an IPv4 packet from
/// `source` to `destination` with `transport`.
fn ipv4_frame(macs: &[u8; 12], source: [u8; 4], destination: [u8; 4], protocol: u8, transport: &[u8]) -> Vec<u8> {
    let total = u16::try_from(20 + transport.len()).unwrap_or(u16::MAX);
    let mut header = [0u8; 20];
    header[0] = 0x45;
    header[2..4].copy_from_slice(&total.to_be_bytes());
    // Don't fragment; it never needs to be.
    header[6] = 0x40;
    header[8] = 64;
    header[9] = protocol;
    header[12..16].copy_from_slice(&source);
    header[16..20].copy_from_slice(&destination);
    let sum = checksum(&[&header[..]]);
    header[10..12].copy_from_slice(&sum.to_be_bytes());
    let mut frame = Vec::with_capacity(34 + transport.len());
    frame.extend_from_slice(macs);
    frame.extend_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
    frame.extend_from_slice(&header);
    frame.extend_from_slice(transport);
    frame
}

/// ICMP "destination unreachable: communication administratively prohibited" from the
/// gateway, about `packet` (its header and first eight bytes, as ICMP quotes them).
fn prohibited(frame: &[u8], packet: &Ipv4<'_>) -> Vec<u8> {
    let quoted = &frame[14..34 + packet.transport.len().min(8)];
    let mut message = Vec::with_capacity(8 + quoted.len());
    message.extend_from_slice(&[3, 13, 0, 0, 0, 0, 0, 0]);
    message.extend_from_slice(quoted);
    let sum = checksum(&[&message[..]]);
    message[2..4].copy_from_slice(&sum.to_be_bytes());
    frame_to_guest(frame, GATEWAY, packet.source, ICMP, &message)
}

/// The filter's own answer to a DNS question the guest sent the resolver over UDP; `None`
/// for something that is no query.
fn dns_answer(frame: &[u8], packet: &Ipv4<'_>, names: &HashMap<String, Vec<[u8; 4]>>) -> Option<Vec<u8>> {
    let (port, _) = packet.ports()?;
    let length = usize::from(u16::from_be_bytes([packet.transport[4], packet.transport[5]]));
    let reply = dns_reply(&packet.transport[8..length], names)?;
    let udp_length = u16::try_from(8 + reply.len()).ok()?;
    let mut datagram = Vec::with_capacity(8 + reply.len());
    datagram.extend_from_slice(&DNS_PORT.to_be_bytes());
    datagram.extend_from_slice(&port.to_be_bytes());
    datagram.extend_from_slice(&udp_length.to_be_bytes());
    datagram.extend_from_slice(&[0, 0]);
    datagram.extend_from_slice(&reply);
    let pseudo = [
        &RESOLVER[..],
        &packet.source[..],
        &[0, UDP][..],
        &udp_length.to_be_bytes()[..],
    ]
    .concat();
    let sum = match checksum(&[&pseudo[..], &datagram[..]]) {
        0 => 0xffff,
        sum => sum,
    };
    datagram[6..8].copy_from_slice(&sum.to_be_bytes());
    Some(frame_to_guest(frame, RESOLVER, packet.source, UDP, &datagram))
}

/// The DNS reply to `query` (RFC 1035): the named host's addresses for an A (or ANY)
/// question, no records for any other type of a named host, "no such name" for every other
/// name, "not implemented" for anything but one standard query. `None` for a message that is
/// a reply or too short to answer.
pub fn dns_reply(query: &[u8], names: &HashMap<String, Vec<[u8; 4]>>) -> Option<Vec<u8>> {
    const NO_ERROR: u16 = 0;
    const FORMAT_ERROR: u16 = 1;
    const NO_SUCH_NAME: u16 = 3;
    const NOT_IMPLEMENTED: u16 = 4;
    if query.len() < 12 {
        return None;
    }
    let flags = u16::from_be_bytes([query[2], query[3]]);
    if flags & 0x8000 != 0 {
        return None;
    }
    let header = |rcode: u16, questions: u16, answers: u16| {
        // A reply, authoritative, the question's "recursion desired", recursion available.
        let flags = 0x8000 | 0x0400 | (flags & 0x0100) | 0x0080 | rcode;
        let mut reply = Vec::with_capacity(DNS_UDP_BYTES);
        reply.extend_from_slice(&query[0..2]);
        reply.extend_from_slice(&flags.to_be_bytes());
        reply.extend_from_slice(&questions.to_be_bytes());
        reply.extend_from_slice(&answers.to_be_bytes());
        reply.extend_from_slice(&[0, 0, 0, 0]);
        reply
    };
    if (flags >> 11) & 0xf != 0 {
        return Some(header(NOT_IMPLEMENTED, 0, 0));
    }
    if u16::from_be_bytes([query[4], query[5]]) != 1 {
        return Some(header(FORMAT_ERROR, 0, 0));
    }
    // The question's name: plain labels only (a query has no compression).
    let mut offset = 12;
    let mut name = String::new();
    loop {
        let Some(&length) = query.get(offset) else {
            return Some(header(FORMAT_ERROR, 0, 0));
        };
        offset += 1;
        if length == 0 {
            break;
        }
        let Some(label) = query.get(offset..offset + usize::from(length)) else {
            return Some(header(FORMAT_ERROR, 0, 0));
        };
        if length > 63 || name.len() + label.len() + 1 > 254 {
            return Some(header(FORMAT_ERROR, 0, 0));
        }
        if !name.is_empty() {
            name.push('.');
        }
        name.extend(label.iter().map(|byte| char::from(byte.to_ascii_lowercase())));
        offset += usize::from(length);
    }
    let Some(fields) = query.get(offset..offset + 4) else {
        return Some(header(FORMAT_ERROR, 0, 0));
    };
    let kind = u16::from_be_bytes([fields[0], fields[1]]);
    let class = u16::from_be_bytes([fields[2], fields[3]]);
    let question = &query[12..offset + 4];
    let internet = matches!(class, 1 | 255);
    let (rcode, addresses): (u16, &[[u8; 4]]) = match names.get(&name) {
        Some(addresses) if internet && matches!(kind, 1 | 255) => (NO_ERROR, addresses),
        Some(_) => (NO_ERROR, &[]),
        None => (NO_SUCH_NAME, &[]),
    };
    // Every answer fits the classic limit: a shorter list of equally allowed addresses.
    let room = DNS_UDP_BYTES.saturating_sub(12 + question.len()) / 16;
    let addresses = &addresses[..addresses.len().min(room)];
    let mut reply = header(rcode, 1, u16::try_from(addresses.len()).unwrap_or(0));
    reply.extend_from_slice(question);
    for address in addresses {
        // The question's name (a pointer to offset 12), type A, class IN.
        reply.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1]);
        reply.extend_from_slice(&DNS_TTL_SECONDS.to_be_bytes());
        reply.extend_from_slice(&[0, 4]);
        reply.extend_from_slice(address);
    }
    Some(reply)
}

/// Frames on their way to one side of the card, in order, at most [`OUTBOX_BYTES`] of them.
/// QEMU sends a frame to the host from its main loop and waits there until the host has read
/// all of it, and that same loop reads what the host sends back: a host that sent each frame
/// before it read the next would, under traffic both ways, wait for QEMU to read while QEMU
/// waits for it to read, and the card would stop. So the threads that read QEMU's frames
/// never wait for a send: they put each frame here and read on, and a thread of its own sends
/// it. A frame that finds the outbox full is dropped, as a congested link drops it (TCP sends
/// it again).
struct Outbox {
    queue: Mutex<Queued>,
    ready: Condvar,
}

#[derive(Default)]
struct Queued {
    frames: VecDeque<Vec<u8>>,
    bytes: usize,
}

impl Outbox {
    fn new() -> Self {
        Self {
            queue: Mutex::new(Queued::default()),
            ready: Condvar::new(),
        }
    }

    /// Queues `frame`, or drops it when the outbox is full.
    fn put(&self, frame: Vec<u8>) -> Result<(), String> {
        self.queue_within(frame, OUTBOX_BYTES)
    }

    /// Queues a released frame, which the guest may have been told arrived: past a full
    /// outbox too, up to [`RELEASED_BYTES`] (a QEMU that takes nothing for so long stops the
    /// card anyway).
    fn put_released(&self, frame: Vec<u8>) -> Result<(), String> {
        self.queue_within(frame, RELEASED_BYTES)
    }

    fn queue_within(&self, frame: Vec<u8>, most: usize) -> Result<(), String> {
        let mut queue = self.queue.lock().map_err(|_| "a frame queue is unavailable")?;
        if queue.bytes + frame.len() <= most {
            queue.bytes += frame.len();
            queue.frames.push_back(frame);
            self.ready.notify_one();
        }
        Ok(())
    }

    /// The next frame, once there is one; `None` when stopped.
    fn take(&self, stop: &AtomicBool) -> Result<Option<Vec<u8>>, String> {
        let mut queue = self.queue.lock().map_err(|_| "a frame queue is unavailable")?;
        loop {
            if stop.load(Ordering::Acquire) {
                return Ok(None);
            }
            if let Some(frame) = queue.frames.pop_front() {
                queue.bytes -= frame.len();
                return Ok(Some(frame));
            }
            queue = self
                .ready
                .wait_timeout(queue, POLL)
                .map_err(|_| "a frame queue is unavailable")?
                .0;
        }
    }
}

/// What one of the filter's threads does until it ends or is stopped.
type Work = Box<dyn FnOnce(&AtomicBool) -> Result<(), String> + Send>;

/// One VM's running filter: a thread judging the guest's frames and one taking the user
/// network's, each into the [`Outbox`] of the side they go to, and a thread sending each
/// outbox's frames on. Dropping it stops them all and closes the sockets, after which the
/// card reaches nothing.
pub struct NetworkFilter {
    stop: Arc<AtomicBool>,
    threads: Vec<JoinHandle<()>>,
}

impl std::fmt::Debug for NetworkFilter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NetworkFilter")
            .field("stopped", &self.stop.load(Ordering::Acquire))
            .finish_non_exhaustive()
    }
}

impl NetworkFilter {
    /// Connects to the four sockets QEMU (process `qemu`) serves in the private directory,
    /// each checked to be served by that process, and starts judging the frames of a card
    /// that may reach `reach`.
    pub fn start(reach: &Reach, sockets: &[HostPath; 4], qemu: u32) -> Result<Self, String> {
        Self::start_with(reach, sockets, qemu, crate::runtime::host_ipv4_addresses)
    }

    pub(crate) fn start_with(
        reach: &Reach,
        sockets: &[HostPath; 4],
        qemu: u32,
        addresses: fn() -> Result<HashSet<[u8; 4]>, String>,
    ) -> Result<Self, String> {
        let timeouts = SocketTimeouts::new(Duration::from_secs(5), Duration::from_secs(5))
            .map_err(|error| error.to_string())?;
        let open = |socket: &HostPath| -> Result<UnixStream, String> {
            let path = Path::new(socket.as_str());
            let started = Instant::now();
            let mut stream = loop {
                match connect(path, timeouts) {
                    Ok(stream) => break stream,
                    Err(error) if started.elapsed() >= CONNECT_WINDOW => {
                        return Err(format!("{} could not be opened: {error}", socket.as_str()))
                    }
                    Err(_) => std::thread::sleep(Duration::from_millis(50)),
                }
            };
            let peer = stream
                .peer_process_id()
                .map_err(|error| format!("the process serving {} could not be read: {error}", socket.as_str()))?;
            if peer != qemu {
                return Err(format!(
                    "{} is served by process {peer}, not by QEMU (process {qemu})",
                    socket.as_str()
                ));
            }
            stream.set_nonblocking(true).map_err(|error| error.to_string())?;
            Ok(stream)
        };
        let from_guest = open(&sockets[0])?;
        let to_network = open(&sockets[1])?;
        let from_network = open(&sockets[2])?;
        let to_guest = open(&sockets[3])?;
        let policy = Policy::new(reach);
        let handshakes = policy.handshakes();
        let outward = Arc::new(Outbox::new());
        let inward = Arc::new(Outbox::new());
        let work: [(&str, Work); 4] = [
            ("vm-network-guest", {
                let (outward, inward) = (Arc::clone(&outward), Arc::clone(&inward));
                Box::new(move |stop: &AtomicBool| judge_guest(from_guest, policy, &outward, &inward, stop, addresses)) as Work
            }),
            ("vm-network-back", {
                let inward = Arc::clone(&inward);
                Box::new(move |stop: &AtomicBool| pass_back(from_network, &handshakes, &inward, stop)) as Work
            }),
            ("vm-network-out", Box::new(move |stop: &AtomicBool| deliver(to_network, &outward, stop)) as Work),
            ("vm-network-in", Box::new(move |stop: &AtomicBool| deliver(to_guest, &inward, stop)) as Work),
        ];
        let stop = Arc::new(AtomicBool::new(false));
        let mut threads = Vec::with_capacity(work.len());
        for (name, work) in work {
            let ending = Arc::clone(&stop);
            let spawned = std::thread::Builder::new().name(name.into()).spawn(move || {
                let ended = work(&ending);
                finish(ended, &ending);
            });
            match spawned {
                Ok(thread) => threads.push(thread),
                Err(error) => {
                    // The threads started so far end, and the sockets of the rest close.
                    stop.store(true, Ordering::Release);
                    for thread in threads {
                        let _ = thread.join();
                    }
                    return Err(format!("a thread of the filter could not start: {error}"));
                }
            }
        }
        Ok(Self { stop, threads })
    }

    /// Whether the filter stopped (its VM ended, or a failure closed its sockets).
    pub fn stopped(&self) -> bool {
        self.stop.load(Ordering::Acquire) || self.threads.iter().any(JoinHandle::is_finished)
    }
}

impl Drop for NetworkFilter {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        for thread in self.threads.drain(..) {
            let _ = thread.join();
        }
    }
}

/// A thread that ended stops the others; a failure is reported, since the card now reaches
/// nothing.
fn finish(ended: Result<(), String>, stop: &AtomicBool) {
    if let Err(error) = ended {
        if !stop.swap(true, Ordering::AcqRel) {
            eprintln!("A Sandbox VM's network filter stopped, so its network card reaches nothing: {error}");
        }
    }
    stop.store(true, Ordering::Release);
}

/// Reads the guest's frames and puts each that may pass in `outward`, and the filter's own
/// answers in `inward`.
fn judge_guest(
    mut from_guest: UnixStream,
    mut policy: Policy,
    outward: &Outbox,
    inward: &Outbox,
    stop: &AtomicBool,
    mut addresses: fn() -> Result<HashSet<[u8; 4]>, String>,
) -> Result<(), String> {
    let mut frame = Vec::with_capacity(2048);
    while read_frame(&mut from_guest, &mut frame, stop)? {
        match policy.from_guest(&frame, Instant::now(), &mut addresses) {
            Verdict::Forward => outward.put(std::mem::take(&mut frame))?,
            Verdict::Drop | Verdict::Held(None) => {}
            Verdict::Answer(answer) | Verdict::Held(Some(answer)) => inward.put(answer)?,
            Verdict::Release(frames) => {
                for released in frames {
                    outward.put_released(released)?;
                }
            }
            Verdict::Reset { guest, network } => {
                inward.put(guest)?;
                if let Some(network) = network {
                    outward.put(network)?;
                }
            }
        }
    }
    Ok(())
}

/// Reads the user network's frames to the guest and puts each in `inward`, noting its
/// answers to the guest's SYNs first, so they are noted before the guest can answer them.
fn pass_back(mut from_network: UnixStream, handshakes: &Handshakes, inward: &Outbox, stop: &AtomicBool) -> Result<(), String> {
    let mut frame = Vec::with_capacity(2048);
    while read_frame(&mut from_network, &mut frame, stop)? {
        handshakes.note(&frame, Instant::now());
        inward.put(std::mem::take(&mut frame))?;
    }
    Ok(())
}

/// Sends `outbox`'s frames on `stream`, in order, until stopped or QEMU ends.
fn deliver(mut stream: UnixStream, outbox: &Outbox, stop: &AtomicBool) -> Result<(), String> {
    while let Some(frame) = outbox.take(stop)? {
        if !write_frame(&mut stream, &frame, stop)? {
            break;
        }
    }
    Ok(())
}

/// Reads one frame as the redirector sends it (a big-endian length, then the frame) into
/// `frame`; `false` at the end of the stream or when stopped.
fn read_frame(stream: &mut UnixStream, frame: &mut Vec<u8>, stop: &AtomicBool) -> Result<bool, String> {
    let mut length = [0u8; 4];
    if !fill(stream, &mut length, stop)? {
        return Ok(false);
    }
    let length = usize::try_from(u32::from_be_bytes(length)).unwrap_or(usize::MAX);
    if !(MIN_FRAME_BYTES..=MAX_FRAME_BYTES).contains(&length) {
        return Err(format!("QEMU sent a frame of {length} bytes"));
    }
    frame.resize(length, 0);
    fill(stream, frame, stop)
}

fn fill(stream: &mut UnixStream, buffer: &mut [u8], stop: &AtomicBool) -> Result<bool, String> {
    let mut filled = 0;
    while filled < buffer.len() {
        if stop.load(Ordering::Acquire) {
            return Ok(false);
        }
        match stream.read(&mut buffer[filled..]) {
            Ok(0) => return Ok(false),
            Ok(count) => filled += count,
            Err(error) if error.kind() == ErrorKind::WouldBlock => {
                stream
                    .wait_ready(Direction::Receive, POLL)
                    .map_err(|error| error.to_string())?;
            }
            Err(error) if error.kind() == ErrorKind::Interrupted => {}
            // QEMU ended: its sockets close, at once or reset.
            Err(error) if ended(&error) => return Ok(false),
            Err(error) => return Err(format!("reading a frame: {error}")),
        }
    }
    Ok(true)
}

/// Writes one frame as the redirector reads it; `false` when stopped first.
fn write_frame(stream: &mut UnixStream, frame: &[u8], stop: &AtomicBool) -> Result<bool, String> {
    let length = u32::try_from(frame.len()).map_err(|_| "a frame too large to send")?;
    let deadline = Instant::now() + WRITE_DEADLINE;
    for part in [&length.to_be_bytes()[..], frame] {
        let mut sent = 0;
        while sent < part.len() {
            if stop.load(Ordering::Acquire) {
                return Ok(false);
            }
            match stream.write(&part[sent..]) {
                Ok(0) => return Err("QEMU stopped taking frames".into()),
                Ok(count) => sent += count,
                Err(error) if error.kind() == ErrorKind::WouldBlock => {
                    if Instant::now() >= deadline {
                        return Err(format!(
                            "QEMU took no frame for {} seconds",
                            WRITE_DEADLINE.as_secs()
                        ));
                    }
                    stream
                        .wait_ready(Direction::Send, POLL)
                        .map_err(|error| error.to_string())?;
                }
                Err(error) if error.kind() == ErrorKind::Interrupted => {}
                Err(error) if ended(&error) => return Ok(false),
                Err(error) => return Err(format!("sending a frame: {error}")),
            }
        }
    }
    Ok(true)
}

/// Whether `error` is the peer's end: QEMU's process ended and its sockets closed.
fn ended(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        ErrorKind::ConnectionReset | ErrorKind::ConnectionAborted | ErrorKind::BrokenPipe | ErrorKind::UnexpectedEof
    )
}

#[cfg(test)]
#[path = "network_filter_tests.rs"]
mod tests;
