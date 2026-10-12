//! Counters fed by the host packet filter (runtime/microvm_network.rs) for monitoring.
//! The filter's allow/deny decisions are unchanged; this only observes them.
use std::{
    collections::{HashMap, HashSet},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex, OnceLock, Weak,
    },
};

/// Why the filter dropped a guest-initiated frame. Only the first two count toward
/// kill-switch rules; the others are shown for context and never trigger anything.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum Denial {
    /// TCP/UDP to the PC: its addresses, the virtual gateway, other gateway aliases or loopback.
    HostPort,
    /// TCP/UDP to link-local addresses, including the cloud metadata service 169.254.169.254.
    Metadata,
    /// Internet destination while this environment's Internet access is off.
    InternetOff,
    /// A source address the guest was not given.
    Spoofed,
    /// IP options, fragments or inconsistent lengths.
    Malformed,
    /// The filter's own safety limits (address inventory unavailable, lookup budget).
    Filter,
    /// IPv6, multicast, broadcast, ICMP and other link chatter.
    Ignored,
}

pub(crate) const DENIALS: [Denial; 7] = [Denial::HostPort, Denial::Metadata, Denial::InternetOff, Denial::Spoofed, Denial::Malformed, Denial::Filter, Denial::Ignored];

impl Denial {
    pub(crate) fn name(self) -> &'static str {
        match self {
            Denial::HostPort => "hostPort",
            Denial::Metadata => "metadata",
            Denial::InternetOff => "internetOff",
            Denial::Spoofed => "spoofed",
            Denial::Malformed => "malformed",
            Denial::Filter => "filter",
            Denial::Ignored => "ignored",
        }
    }
    fn index(self) -> usize {
        DENIALS.iter().position(|denial| *denial == self).unwrap_or(0)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Classified {
    pub class: Denial,
    pub protocol: u8,
    pub peer: [u8; 4],
    pub peer_port: u16,
    pub guest_port: u16,
    /// A new TCP connection (SYN) or a UDP datagram, as opposed to a stray segment.
    pub attempt: bool,
}

fn word(bytes: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([bytes[at], bytes[at + 1]])
}

/// Classifies a guest→outside frame that the filter refused.
pub(crate) fn classify(packet: &[u8], host_addresses: &HashSet<[u8; 4]>, internet: bool) -> Classified {
    let mut result = Classified { class: Denial::Malformed, protocol: 0, peer: [0; 4], peer_port: 0, guest_port: 0, attempt: false };
    if packet.len() < 14 {
        return result;
    }
    if word(packet, 12) != 0x0800 {
        result.class = Denial::Ignored;
        return result;
    }
    if packet.len() < 34 || packet[14] >> 4 != 4 || packet[14] & 15 != 5 {
        return result;
    }
    let total = usize::from(word(packet, 16));
    if total < 20 || packet.len() < 14 + total || word(packet, 20) & 0x3fff != 0 {
        return result;
    }
    let source: [u8; 4] = packet[26..30].try_into().unwrap();
    let peer: [u8; 4] = packet[30..34].try_into().unwrap();
    result.peer = peer;
    result.protocol = packet[23];
    if peer[0] >= 224 {
        result.class = Denial::Ignored;
        return result;
    }
    let transport = &packet[34..14 + total];
    match result.protocol {
        6 if transport.len() >= 20 => {
            result.guest_port = word(transport, 0);
            result.peer_port = word(transport, 2);
            result.attempt = transport[13] & 0x12 == 0x02;
        }
        17 if transport.len() >= 8 => {
            result.guest_port = word(transport, 0);
            result.peer_port = word(transport, 2);
            result.attempt = true;
        }
        6 | 17 => return result,
        _ => {
            result.class = Denial::Ignored;
            return result;
        }
    }
    if !(source[..3] == [10, 0, 2] && (4..=254).contains(&source[3])) {
        result.class = Denial::Spoofed;
        return result;
    }
    result.class = if peer[..2] == [169, 254] {
        Denial::Metadata
    } else if peer == [10, 0, 2, 2] || peer[0] == 127 || peer[0] == 0 || host_addresses.contains(&peer) {
        Denial::HostPort
    } else if peer[..3] == [10, 0, 2] {
        if peer[3] == 3 && result.peer_port == 53 {
            if internet { Denial::Filter } else { Denial::InternetOff }
        } else {
            Denial::HostPort
        }
    } else if internet {
        Denial::Filter
    } else {
        Denial::InternetOff
    };
    result
}

const MAX_ATTEMPTS: usize = 2048;
const MAX_HOST_PORTS: usize = 1024;
const MAX_LINK_LOCAL: usize = 256;
const MAX_PEERS: usize = 4096;

/// What the filter saw since the monitor last drained it.
#[derive(Clone, Debug, Default)]
pub(crate) struct Window {
    /// Dropped packets by class (index order of `DENIALS`).
    pub packets: [u64; 7],
    /// Distinct new attempts by class (TCP SYN / UDP tuples).
    pub attempts: [u64; 7],
    pub host_ports: HashSet<u16>,
    pub link_local: HashSet<([u8; 4], u16)>,
    /// Distinct Internet destinations of allowed new connections.
    pub peers: HashSet<([u8; 4], u16)>,
    tuples: HashSet<(u8, u8, [u8; 4], u16, u16)>,
    udp_flows: HashSet<([u8; 4], u16, u16)>,
}

impl Window {
    pub(crate) fn packets(&self, class: Denial) -> u64 {
        self.packets[class.index()]
    }
    pub(crate) fn attempts(&self, class: Denial) -> u64 {
        self.attempts[class.index()]
    }
}

/// Cumulative byte and connection counters plus the current window.
#[derive(Debug, Default)]
pub(crate) struct FilterStats {
    egress_bytes: AtomicU64,
    ingress_bytes: AtomicU64,
    connections: AtomicU64,
    window: Mutex<Window>,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct Drained {
    pub egress_bytes: u64,
    pub ingress_bytes: u64,
    pub connections: u64,
    pub window: Window,
}

fn internet_peer(peer: [u8; 4], host_addresses: &HashSet<[u8; 4]>) -> bool {
    peer[0] != 0 && peer[0] != 127 && peer[..2] != [169, 254] && peer[0] < 224 && peer[..3] != [10, 0, 2] && !host_addresses.contains(&peer)
}

impl FilterStats {
    /// A frame the filter forwarded. `outbound` is guest→outside.
    pub(crate) fn allowed(&self, packet: &[u8], outbound: bool, host_addresses: &HashSet<[u8; 4]>) {
        if packet.len() < 34 || word(packet, 12) != 0x0800 || packet[14] & 15 != 5 {
            return;
        }
        let total = usize::from(word(packet, 16));
        if total < 20 || packet.len() < 14 + total {
            return;
        }
        let peer: [u8; 4] = if outbound { packet[30..34].try_into().unwrap() } else { packet[26..30].try_into().unwrap() };
        if !internet_peer(peer, host_addresses) {
            return;
        }
        if !outbound {
            self.ingress_bytes.fetch_add(total as u64, Ordering::Relaxed);
            return;
        }
        self.egress_bytes.fetch_add(total as u64, Ordering::Relaxed);
        let transport = &packet[34..14 + total];
        let (new, port, guest_port) = match packet[23] {
            6 if transport.len() >= 20 => (transport[13] & 0x12 == 0x02, word(transport, 2), word(transport, 0)),
            17 if transport.len() >= 8 => (true, word(transport, 2), word(transport, 0)),
            _ => (false, 0, 0),
        };
        if !new {
            return;
        }
        let mut window = self.window.lock().unwrap_or_else(|error| error.into_inner());
        if packet[23] == 17 {
            if window.udp_flows.len() >= MAX_PEERS || !window.udp_flows.insert((peer, port, guest_port)) {
                return;
            }
        }
        self.connections.fetch_add(1, Ordering::Relaxed);
        if window.peers.len() < MAX_PEERS {
            window.peers.insert((peer, port));
        }
    }

    /// A guest→outside frame the filter refused.
    pub(crate) fn denied(&self, packet: &[u8], host_addresses: &HashSet<[u8; 4]>, internet: bool) {
        let classified = classify(packet, host_addresses, internet);
        let index = classified.class.index();
        let mut window = self.window.lock().unwrap_or_else(|error| error.into_inner());
        window.packets[index] += 1;
        if !classified.attempt || classified.class == Denial::Ignored {
            return;
        }
        let tuple = (index as u8, classified.protocol, classified.peer, classified.peer_port, classified.guest_port);
        // Retransmitted SYNs repeat their tuple; a full set still counts new attempts.
        if window.tuples.len() >= MAX_ATTEMPTS || window.tuples.insert(tuple) {
            window.attempts[index] += 1;
        }
        match classified.class {
            Denial::HostPort if window.host_ports.len() < MAX_HOST_PORTS => {
                window.host_ports.insert(classified.peer_port);
            }
            Denial::Metadata if window.link_local.len() < MAX_LINK_LOCAL => {
                window.link_local.insert((classified.peer, classified.peer_port));
            }
            _ => {}
        }
    }

    pub(crate) fn drain(&self) -> Drained {
        let window = std::mem::take(&mut *self.window.lock().unwrap_or_else(|error| error.into_inner()));
        Drained {
            egress_bytes: self.egress_bytes.load(Ordering::Relaxed),
            ingress_bytes: self.ingress_bytes.load(Ordering::Relaxed),
            connections: self.connections.load(Ordering::Relaxed),
            window,
        }
    }
}

fn registry() -> &'static Mutex<HashMap<String, Weak<FilterStats>>> {
    static REGISTRY: OnceLock<Mutex<HashMap<String, Weak<FilterStats>>>> = OnceLock::new();
    REGISTRY.get_or_init(Default::default)
}

/// New counters for one filter. `key` is the VM's runtime ID, or `appliance:<storage root>`
/// for a container appliance. The counters live as long as the filter holds them.
pub(crate) fn register(key: &str) -> Arc<FilterStats> {
    let stats = Arc::new(FilterStats::default());
    let mut registry = registry().lock().unwrap_or_else(|error| error.into_inner());
    registry.retain(|_, stats| stats.strong_count() > 0);
    registry.insert(key.to_owned(), Arc::downgrade(&stats));
    stats
}

/// Every live filter's counters by key.
pub(crate) fn live() -> Vec<(String, Arc<FilterStats>)> {
    let mut registry = registry().lock().unwrap_or_else(|error| error.into_inner());
    registry.retain(|_, stats| stats.strong_count() > 0);
    registry.iter().filter_map(|(key, stats)| stats.upgrade().map(|stats| (key.clone(), stats))).collect()
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn frame(source: [u8; 4], target: [u8; 4], protocol: u8, from: u16, to: u16, flags: u8) -> Vec<u8> {
        let transport = if protocol == 6 { 20 } else if protocol == 17 { 8 } else { 8 };
        let total = 20 + transport;
        let mut packet = vec![0u8; 14 + total];
        packet[12..14].copy_from_slice(&[8, 0]);
        packet[14] = 0x45;
        packet[16..18].copy_from_slice(&(total as u16).to_be_bytes());
        packet[23] = protocol;
        packet[26..30].copy_from_slice(&source);
        packet[30..34].copy_from_slice(&target);
        packet[34..36].copy_from_slice(&from.to_be_bytes());
        packet[36..38].copy_from_slice(&to.to_be_bytes());
        if protocol == 6 {
            packet[46] = 0x50;
            packet[47] = flags;
        }
        packet
    }

    const GUEST: [u8; 4] = [10, 0, 2, 15];
    const SYN: u8 = 0x02;

    #[test]
    fn denied_frames_are_classified_by_destination() {
        let host = HashSet::from([[192, 168, 1, 20]]);
        let class = |target: [u8; 4], protocol: u8, port: u16, internet: bool| classify(&frame(GUEST, target, protocol, 40000, port, SYN), &host, internet).class;
        assert_eq!(class([10, 0, 2, 2], 6, 4444, true), Denial::HostPort);
        assert_eq!(class([192, 168, 1, 20], 6, 5900, false), Denial::HostPort);
        assert_eq!(class([127, 0, 0, 1], 17, 53, true), Denial::HostPort);
        assert_eq!(class([10, 0, 2, 7], 6, 22, true), Denial::HostPort);
        assert_eq!(class([169, 254, 169, 254], 6, 80, true), Denial::Metadata);
        assert_eq!(class([1, 1, 1, 1], 6, 443, false), Denial::InternetOff);
        assert_eq!(class([10, 0, 2, 3], 17, 53, false), Denial::InternetOff);
        assert_eq!(class([1, 1, 1, 1], 6, 443, true), Denial::Filter);
        assert_eq!(class([224, 0, 0, 251], 17, 5353, true), Denial::Ignored);
        assert_eq!(class([1, 1, 1, 1], 1, 0, true), Denial::Ignored);
        assert_eq!(classify(&frame([172, 17, 0, 2], [1, 1, 1, 1], 6, 1, 443, SYN), &host, true).class, Denial::Spoofed);
        let mut ipv6 = frame(GUEST, [1, 1, 1, 1], 6, 1, 2, SYN);
        ipv6[12..14].copy_from_slice(&[0x86, 0xdd]);
        assert_eq!(classify(&ipv6, &host, true).class, Denial::Ignored);
        let mut fragment = frame(GUEST, [10, 0, 2, 2], 6, 1, 2, SYN);
        fragment[20] = 0x20;
        assert_eq!(classify(&fragment, &host, true).class, Denial::Malformed);
        assert!(!classify(&frame(GUEST, [10, 0, 2, 2], 6, 1, 2, 0x10), &host, true).attempt);
    }

    #[test]
    fn retransmissions_count_once_and_windows_drain() {
        let stats = FilterStats::default();
        let host = HashSet::new();
        for _ in 0..3 {
            stats.denied(&frame(GUEST, [10, 0, 2, 2], 6, 40000, 4444, SYN), &host, true);
        }
        for port in 1..=5 {
            stats.denied(&frame(GUEST, [10, 0, 2, 2], 6, 40001, port, SYN), &host, true);
        }
        stats.denied(&frame(GUEST, [169, 254, 169, 254], 6, 40002, 80, SYN), &host, true);
        stats.denied(&frame(GUEST, [224, 0, 0, 251], 17, 5353, 5353, 0), &host, true);
        let drained = stats.drain();
        assert_eq!(drained.window.packets(Denial::HostPort), 8);
        assert_eq!(drained.window.attempts(Denial::HostPort), 6);
        assert_eq!(drained.window.host_ports.len(), 6);
        assert_eq!(drained.window.attempts(Denial::Metadata), 1);
        assert_eq!(drained.window.packets(Denial::Ignored), 1);
        assert_eq!(drained.window.attempts(Denial::Ignored), 0);
        assert_eq!(stats.drain().window.packets(Denial::HostPort), 0);
    }

    #[test]
    fn allowed_internet_traffic_counts_bytes_and_new_connections_only() {
        let stats = FilterStats::default();
        let host = HashSet::from([[192, 168, 1, 20]]);
        let syn = frame(GUEST, [93, 184, 216, 34], 6, 40000, 443, SYN);
        stats.allowed(&syn, true, &host);
        stats.allowed(&frame(GUEST, [93, 184, 216, 34], 6, 40000, 443, 0x10), true, &host);
        stats.allowed(&frame([93, 184, 216, 34], GUEST, 6, 443, 40000, 0x12), false, &host);
        stats.allowed(&frame(GUEST, [10, 0, 2, 3], 17, 5000, 53, 0), true, &host);
        stats.allowed(&frame(GUEST, [192, 168, 1, 20], 6, 40001, 8080, SYN), true, &host);
        for _ in 0..3 {
            stats.allowed(&frame(GUEST, [8, 8, 8, 8], 17, 6000, 443, 0), true, &host);
        }
        let drained = stats.drain();
        assert_eq!(drained.connections, 2, "one TCP SYN and one new UDP flow");
        assert_eq!(drained.window.peers.len(), 2);
        assert_eq!(drained.egress_bytes, (syn.len() - 14) as u64 * 2 + 3 * 28);
        assert_eq!(drained.ingress_bytes, 40);
    }

    #[test]
    fn registry_drops_counters_with_their_filter() {
        let stats = register("test-registry-vm");
        assert!(live().iter().any(|(key, _)| key == "test-registry-vm"));
        drop(stats);
        assert!(!live().iter().any(|(key, _)| key == "test-registry-vm"));
    }
}
