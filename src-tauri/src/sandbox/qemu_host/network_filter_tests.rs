//! The host network filter's decisions (targets, the public internet, DNS answers, this
//! computer never reached, malformed frames) and its run between the sockets QEMU serves.

use super::*;

const GUEST: [u8; 4] = [10, 0, 2, 15];
const GUEST_MAC: [u8; 6] = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];
const GATEWAY_MAC: [u8; 6] = [0x52, 0x55, 0x0a, 0x00, 0x02, 0x02];
const STAGING: [u8; 4] = [93, 184, 216, 34];
const LAN_SERVER: [u8; 4] = [192, 168, 1, 50];
const THIS_PC: [u8; 4] = [192, 168, 1, 10];

fn target(host: &str, addresses: &[[u8; 4]], ports: &[u16]) -> NetworkTarget {
    NetworkTarget {
        host: host.into(),
        addresses: addresses.iter().map(|octets| Ipv4Addr::from(*octets)).collect(),
        ports: ports.to_vec(),
    }
}

fn targets() -> Reach {
    Reach::Targets(vec![
        target("staging.mycompany.com", &[STAGING], &[443]),
        target("192.168.1.50", &[LAN_SERVER], &[8080]),
        target("10.1.2.3", &[[10, 1, 2, 3]], &[]),
        // This computer's address, as if it had been named: still never reached.
        target("192.168.1.10", &[THIS_PC], &[]),
    ])
}

/// A public address this computer holds (a server with a public address of its own).
const THIS_PC_PUBLIC: [u8; 4] = [81, 2, 69, 142];

/// This computer's addresses as the inventory reads them.
fn this_computer() -> Result<HashSet<[u8; 4]>, String> {
    Ok(HashSet::from([[127, 0, 0, 1], THIS_PC, THIS_PC_PUBLIC]))
}

fn judge(policy: &mut Policy, frame: &[u8]) -> Verdict {
    policy.from_guest(frame, Instant::now(), &mut this_computer)
}

fn ipv4_frame(source: [u8; 4], destination: [u8; 4], protocol: u8, transport: &[u8]) -> Vec<u8> {
    let mut frame = Vec::new();
    frame.extend_from_slice(&GATEWAY_MAC);
    frame.extend_from_slice(&GUEST_MAC);
    frame.extend_from_slice(&[0x08, 0x00]);
    let mut header = [0u8; 20];
    header[0] = 0x45;
    header[2..4].copy_from_slice(&u16::try_from(20 + transport.len()).unwrap().to_be_bytes());
    header[8] = 64;
    header[9] = protocol;
    header[12..16].copy_from_slice(&source);
    header[16..20].copy_from_slice(&destination);
    frame.extend_from_slice(&header);
    frame.extend_from_slice(transport);
    frame
}

fn tcp(destination: [u8; 4], port: u16, flags: u8) -> Vec<u8> {
    let mut segment = vec![0u8; 20];
    segment[0..2].copy_from_slice(&40000u16.to_be_bytes());
    segment[2..4].copy_from_slice(&port.to_be_bytes());
    segment[4..8].copy_from_slice(&7u32.to_be_bytes());
    segment[12] = 0x50;
    segment[13] = flags;
    ipv4_frame(GUEST, destination, TCP, &segment)
}

const SYN: u8 = 0x02;
const ACK: u8 = 0x10;

fn udp(destination: [u8; 4], port: u16, payload: &[u8]) -> Vec<u8> {
    let mut datagram = vec![0u8; 8];
    datagram[0..2].copy_from_slice(&41000u16.to_be_bytes());
    datagram[2..4].copy_from_slice(&port.to_be_bytes());
    datagram[4..6].copy_from_slice(&u16::try_from(8 + payload.len()).unwrap().to_be_bytes());
    datagram.extend_from_slice(payload);
    ipv4_frame(GUEST, destination, UDP, &datagram)
}

fn ping(destination: [u8; 4]) -> Vec<u8> {
    ipv4_frame(GUEST, destination, ICMP, &[8, 0, 0, 0, 0, 1, 0, 1])
}

/// A DNS query for `name` of type `kind`, recursion desired.
fn dns_query(id: u16, name: &str, kind: u16) -> Vec<u8> {
    let mut query = Vec::new();
    query.extend_from_slice(&id.to_be_bytes());
    query.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
    for label in name.split('.') {
        query.push(u8::try_from(label.len()).unwrap());
        query.extend_from_slice(label.as_bytes());
    }
    query.push(0);
    query.extend_from_slice(&kind.to_be_bytes());
    query.extend_from_slice(&1u16.to_be_bytes());
    query
}

fn valid_checksum(parts: &[&[u8]]) -> bool {
    checksum(parts) == 0
}

/// The DNS message, the UDP ports and the addresses of a frame the filter sent the guest,
/// every header and checksum checked on the way.
fn dns_of(answer: &[u8]) -> (Vec<u8>, u16) {
    assert_eq!(&answer[0..6], &GUEST_MAC, "to the guest");
    assert_eq!(&answer[6..12], &GATEWAY_MAC, "from the MAC the guest addressed");
    assert_eq!(&answer[12..14], &[0x08, 0x00]);
    assert!(valid_checksum(&[&answer[14..34]]), "IPv4 header checksum");
    assert_eq!(answer[23], UDP);
    assert_eq!(&answer[26..30], &RESOLVER);
    assert_eq!(&answer[30..34], &GUEST);
    let datagram = &answer[34..];
    assert_eq!(u16::from_be_bytes([datagram[0], datagram[1]]), 53);
    let length = usize::from(u16::from_be_bytes([datagram[4], datagram[5]]));
    assert_eq!(length, datagram.len());
    let pseudo = [&RESOLVER[..], &GUEST[..], &[0, UDP][..], &datagram[4..6]].concat();
    assert!(valid_checksum(&[&pseudo[..], datagram]), "UDP checksum");
    (datagram[8..].to_vec(), u16::from_be_bytes([datagram[2], datagram[3]]))
}

fn rcode(reply: &[u8]) -> u16 {
    u16::from_be_bytes([reply[2], reply[3]]) & 0xf
}

fn answer_count(reply: &[u8]) -> u16 {
    u16::from_be_bytes([reply[6], reply[7]])
}

/// Asserts `verdict` is the ICMP "administratively prohibited" answer to `request`.
fn assert_prohibited(verdict: Verdict, request: &[u8]) {
    let Verdict::Answer(answer) = verdict else {
        panic!("expected a refusal answer, got {verdict:?}");
    };
    assert_eq!(&answer[0..6], &GUEST_MAC);
    assert!(valid_checksum(&[&answer[14..34]]));
    assert_eq!(answer[23], ICMP);
    assert_eq!(&answer[26..30], &GATEWAY);
    assert_eq!(&answer[30..34], &GUEST);
    let message = &answer[34..];
    assert_eq!((message[0], message[1]), (3, 13), "communication administratively prohibited");
    assert!(valid_checksum(&[message]));
    // It quotes the refused packet's header and first eight bytes, as ICMP does.
    assert_eq!(&message[8..36], &request[14..42]);
}

#[test]
fn targets_reach_only_their_addresses_and_ports() {
    let mut policy = Policy::new(&targets());
    for frame in [
        tcp(STAGING, 443, SYN),
        tcp(STAGING, 443, ACK),
        tcp(LAN_SERVER, 8080, SYN),
        tcp([10, 1, 2, 3], 22, SYN),
        tcp([10, 1, 2, 3], 65535, ACK),
    ] {
        assert_eq!(judge(&mut policy, &frame), Verdict::Forward);
    }
    // Another port of a named address, an address nobody named, UDP to a named address.
    for frame in [
        tcp(STAGING, 80, SYN),
        tcp(LAN_SERVER, 8081, SYN),
        tcp([192, 168, 1, 51], 8080, SYN),
        tcp([1, 1, 1, 1], 443, SYN),
        udp(STAGING, 443, b"quic"),
        udp(LAN_SERVER, 8080, b"x"),
    ] {
        assert_prohibited(judge(&mut policy, &frame), &frame);
    }
    // No answer to what opens nothing: a stray segment, a ping.
    assert_eq!(judge(&mut policy, &tcp([1, 1, 1, 1], 443, ACK)), Verdict::Drop);
    assert_eq!(judge(&mut policy, &ping(STAGING)), Verdict::Drop);
}

#[test]
fn this_computer_is_never_reached_through_the_gateway_or_its_addresses() {
    for reach in [targets(), Reach::PublicInternet] {
        let mut policy = Policy::new(&reach);
        // QEMU turns the gateway and every other user-network address into this computer's
        // loopback; this computer's own addresses are refused even when named.
        for frame in [
            tcp(GATEWAY, 8080, SYN),
            tcp(GATEWAY, 3389, SYN),
            tcp([10, 0, 2, 99], 80, SYN),
            tcp(THIS_PC, 445, SYN),
            tcp(THIS_PC, 8080, SYN),
            tcp([127, 0, 0, 1], 80, SYN),
            udp(GATEWAY, 1900, b"x"),
        ] {
            assert_prohibited(judge(&mut policy, &frame), &frame);
        }
        assert_eq!(judge(&mut policy, &tcp(GATEWAY, 8080, ACK)), Verdict::Drop);
    }
    // A public address this computer holds is this computer too.
    let mut public = Policy::new(&Reach::PublicInternet);
    let frame = tcp(THIS_PC_PUBLIC, 443, SYN);
    assert_prohibited(judge(&mut public, &frame), &frame);
}

#[test]
fn dns_is_answered_inside_the_filter_for_named_hosts_alone() {
    let mut policy = Policy::new(&targets());
    // A named host, asked in mixed case: its launch-time address, the question as asked.
    let query = dns_query(0x1234, "Staging.MyCompany.com", 1);
    let Verdict::Answer(answer) = judge(&mut policy, &udp(RESOLVER, 53, &query)) else {
        panic!("a named host is answered");
    };
    let (reply, port) = dns_of(&answer);
    assert_eq!(port, 41000, "back to the asking port");
    assert_eq!(&reply[0..2], &[0x12, 0x34]);
    assert_eq!(reply[2] & 0x80, 0x80, "a reply");
    assert_eq!((rcode(&reply), answer_count(&reply)), (0, 1));
    assert_eq!(&reply[12..12 + query.len() - 12], &query[12..], "the question echoed");
    let record = &reply[query.len()..];
    assert_eq!(&record[0..2], &[0xc0, 0x0c]);
    assert_eq!(&record[2..6], &[0, 1, 0, 1], "type A, class IN");
    assert_eq!(&record[10..12], &[0, 4]);
    assert_eq!(&record[12..16], &STAGING);
    // Other types of a named host: no records. Any other name: no such name.
    let Verdict::Answer(answer) = judge(&mut policy, &udp(RESOLVER, 53, &dns_query(7, "staging.mycompany.com", 28))) else {
        panic!("AAAA is answered");
    };
    let (reply, _) = dns_of(&answer);
    assert_eq!((rcode(&reply), answer_count(&reply)), (0, 0));
    for name in ["example.org", "mycompany.com", "www.staging.mycompany.com", "192.168.1.50", "localhost"] {
        let Verdict::Answer(answer) = judge(&mut policy, &udp(RESOLVER, 53, &dns_query(9, name, 1))) else {
            panic!("{name} is answered");
        };
        let (reply, _) = dns_of(&answer);
        assert_eq!((rcode(&reply), answer_count(&reply)), (3, 0), "{name}");
    }
    // No question leaves: another resolver, DNS over TCP, a stray reply.
    let elsewhere = udp([8, 8, 8, 8], 53, &dns_query(1, "example.org", 1));
    assert_prohibited(judge(&mut policy, &elsewhere), &elsewhere);
    let over_tcp = tcp(RESOLVER, 53, SYN);
    assert_prohibited(judge(&mut policy, &over_tcp), &over_tcp);
    let mut reply = dns_query(1, "example.org", 1);
    reply[2] |= 0x80;
    assert_eq!(judge(&mut policy, &udp(RESOLVER, 53, &reply)), Verdict::Drop);
    assert_eq!(judge(&mut policy, &udp(RESOLVER, 53, &[0; 5])), Verdict::Drop);
}

#[test]
fn dns_replies_stay_well_formed_and_within_the_classic_limit() {
    let many: Vec<[u8; 4]> = (0..60).map(|index| [93, 184, 1, index]).collect();
    let names = HashMap::from([("big.example.com".to_owned(), many)]);
    let reply = dns_reply(&dns_query(1, "big.example.com", 1), &names).unwrap();
    assert!(reply.len() <= DNS_UDP_BYTES);
    assert!(answer_count(&reply) >= 25);
    // Not a standard query, two questions, a compressed name: refused, never guessed.
    let mut other = dns_query(1, "big.example.com", 1);
    other[2] |= 0x28;
    assert_eq!(rcode(&dns_reply(&other, &names).unwrap()), 4);
    let mut two = dns_query(1, "big.example.com", 1);
    two[5] = 2;
    assert_eq!(rcode(&dns_reply(&two, &names).unwrap()), 1);
    let mut pointer = dns_query(1, "big.example.com", 1);
    pointer[12] = 0xc0;
    assert_eq!(rcode(&dns_reply(&pointer, &names).unwrap()), 1);
    let truncated = &dns_query(1, "big.example.com", 1)[..20];
    assert_eq!(rcode(&dns_reply(truncated, &names).unwrap()), 1);
    // An ANY question of a named host gets its addresses; another class gets none.
    assert!(answer_count(&dns_reply(&dns_query(1, "big.example.com", 255), &names).unwrap()) > 0);
    let mut chaos = dns_query(1, "big.example.com", 1);
    let class = chaos.len() - 1;
    chaos[class] = 3;
    assert_eq!(answer_count(&dns_reply(&chaos, &names).unwrap()), 0);
}

#[test]
fn full_internet_is_the_public_internet_only() {
    let mut policy = Policy::new(&Reach::PublicInternet);
    for frame in [
        tcp([1, 1, 1, 1], 443, SYN),
        tcp(STAGING, 22, SYN),
        udp([8, 8, 8, 8], 53, &dns_query(1, "example.org", 1)),
        udp(RESOLVER, 53, &dns_query(1, "example.org", 1)),
        ping([1, 1, 1, 1]),
        ping(GATEWAY),
        // Public space right beside the reserved ranges.
        tcp([198, 17, 255, 255], 443, SYN),
        tcp([198, 20, 0, 1], 443, SYN),
        tcp([192, 88, 98, 1], 443, SYN),
        tcp([203, 0, 114, 1], 443, SYN),
    ] {
        assert_eq!(judge(&mut policy, &frame), Verdict::Forward);
    }
    // The person's network, VPNs and shared space, link-local and cloud management, this
    // computer's loopback, multicast and broadcast.
    for destination in [
        [192, 168, 1, 5],
        LAN_SERVER,
        [10, 9, 9, 9],
        [172, 20, 0, 1],
        [100, 64, 0, 1],
        [100, 100, 100, 200],
        [169, 254, 169, 254],
        [168, 63, 129, 16],
        [192, 0, 0, 192],
        [127, 0, 0, 1],
        [0, 0, 0, 0],
        [224, 0, 0, 251],
        [255, 255, 255, 255],
        // Reserved, not globally reachable: benchmarking, documentation, the 6to4 relay.
        [198, 18, 0, 1],
        [198, 19, 255, 254],
        [192, 0, 2, 10],
        [198, 51, 100, 7],
        [203, 0, 113, 9],
        [192, 88, 99, 1],
    ] {
        let frame = tcp(destination, 80, SYN);
        assert_prohibited(judge(&mut policy, &frame), &frame);
        assert_eq!(judge(&mut policy, &ping(destination)), Verdict::Drop, "{destination:?}");
    }
}

#[test]
fn an_unreadable_address_list_refuses_and_a_fresh_one_applies() {
    let mut policy = Policy::new(&Reach::PublicInternet);
    let frame = tcp([1, 1, 1, 1], 443, SYN);
    let now = Instant::now();
    let mut failing = || -> Result<HashSet<[u8; 4]>, String> { Err("injected".into()) };
    assert_prohibited(policy.from_guest(&frame, now, &mut failing), &frame);
    let mut empty = || -> Result<HashSet<[u8; 4]>, String> { Ok(HashSet::new()) };
    let later = now + ADDRESS_RETRY;
    assert_prohibited(policy.from_guest(&frame, later, &mut empty), &frame);
    // A reading lasts its lease; then the list is read again, and a new address is refused.
    let mut reads = 0;
    let mut first = || -> Result<HashSet<[u8; 4]>, String> {
        reads += 1;
        Ok(HashSet::from([[127, 0, 0, 1]]))
    };
    let start = later + ADDRESS_RETRY;
    assert_eq!(policy.from_guest(&frame, start, &mut first), Verdict::Forward);
    assert_eq!(policy.from_guest(&frame, start + Duration::from_millis(500), &mut first), Verdict::Forward);
    assert_eq!(reads, 1);
    let mut moved = || -> Result<HashSet<[u8; 4]>, String> { Ok(HashSet::from([[1, 1, 1, 1]])) };
    assert_prohibited(policy.from_guest(&frame, start + ADDRESS_LEASE, &mut moved), &frame);
}

#[test]
fn malformed_spoofed_and_other_frames_are_dropped() {
    for reach in [targets(), Reach::PublicInternet] {
        let mut policy = Policy::new(&reach);
        let mut ipv6 = tcp([1, 1, 1, 1], 443, SYN);
        ipv6[12..14].copy_from_slice(&[0x86, 0xdd]);
        let mut options = tcp(STAGING, 443, SYN);
        options[14] = 0x46;
        let mut fragment = tcp(STAGING, 443, SYN);
        fragment[20] = 0x20;
        let mut offset = tcp(STAGING, 443, SYN);
        offset[21] = 0x01;
        let mut truncated = tcp(STAGING, 443, SYN);
        truncated[17] = 0xff;
        let mut short_header = tcp(STAGING, 443, SYN);
        short_header[46] = 0x40;
        let mut gateway_source = tcp(STAGING, 443, SYN);
        gateway_source[26..30].copy_from_slice(&GATEWAY);
        let mut lan_source = tcp(STAGING, 443, SYN);
        lan_source[26..30].copy_from_slice(&[192, 168, 1, 77]);
        for frame in [ipv6, options, fragment, offset, truncated, short_header, gateway_source, lan_source, vec![0; 13], vec![0; MAX_FRAME_BYTES + 1]] {
            assert_eq!(judge(&mut policy, &frame), Verdict::Drop);
        }
        let mut arp = vec![0u8; 42];
        arp[12..20].copy_from_slice(&[0x08, 0x06, 0, 1, 8, 0, 6, 4]);
        assert_eq!(judge(&mut policy, &arp), Verdict::Forward);
        // DHCP to the user network's own server, before and after the guest has an address.
        let mut bootstrap = udp(BROADCAST, 67, b"discover");
        bootstrap[26..30].copy_from_slice(&[0; 4]);
        bootstrap[34..36].copy_from_slice(&68u16.to_be_bytes());
        assert_eq!(judge(&mut policy, &bootstrap), Verdict::Forward);
        let mut renew = udp(GATEWAY, 67, b"request");
        renew[34..36].copy_from_slice(&68u16.to_be_bytes());
        assert_eq!(judge(&mut policy, &renew), Verdict::Forward);
        let mut unaddressed = tcp(STAGING, 443, SYN);
        unaddressed[26..30].copy_from_slice(&[0; 4]);
        assert_eq!(judge(&mut policy, &unaddressed), Verdict::Drop);
    }
}

#[test]
fn a_host_named_twice_keeps_every_port_it_was_named_with() {
    let mut policy = Policy::new(&Reach::Targets(vec![
        target("app.example.com", &[STAGING], &[443]),
        target("app.example.com", &[STAGING], &[8443]),
        target("93.184.216.34", &[STAGING], &[]),
    ]));
    assert_eq!(judge(&mut policy, &tcp(STAGING, 22, SYN)), Verdict::Forward, "named once with every port");
    let mut ports = Policy::new(&Reach::Targets(vec![
        target("app.example.com", &[STAGING], &[443]),
        target("app.example.com", &[STAGING], &[8443]),
    ]));
    assert_eq!(judge(&mut ports, &tcp(STAGING, 8443, SYN)), Verdict::Forward);
    let frame = tcp(STAGING, 22, SYN);
    assert_prohibited(judge(&mut ports, &frame), &frame);
}

#[test]
fn an_outbox_keeps_its_frames_in_order_and_drops_what_does_not_fit() {
    let outbox = Outbox::new();
    let stop = AtomicBool::new(false);
    let size = 1 << 20;
    let frame = |index: usize| vec![u8::try_from(index).unwrap(); size];
    let fits = OUTBOX_BYTES / size;
    for index in 0..fits {
        outbox.put(frame(index)).unwrap();
    }
    // Full: the next frames are dropped, as a congested link drops them.
    outbox.put(frame(fits)).unwrap();
    outbox.put(vec![0xee; MIN_FRAME_BYTES]).unwrap();
    assert_eq!(outbox.take(&stop).unwrap(), Some(frame(0)));
    // What fits again is kept, after what was already waiting.
    outbox.put(vec![0xee; MIN_FRAME_BYTES]).unwrap();
    for index in 1..fits {
        assert_eq!(outbox.take(&stop).unwrap(), Some(frame(index)));
    }
    assert_eq!(outbox.take(&stop).unwrap(), Some(vec![0xee; MIN_FRAME_BYTES]));
    // Stopped: nothing more, whatever is queued.
    outbox.put(vec![0xef; MIN_FRAME_BYTES]).unwrap();
    stop.store(true, Ordering::Release);
    assert_eq!(outbox.take(&stop).unwrap(), None);
}

#[test]
fn released_frames_go_past_a_full_outbox_up_to_their_own_bound() {
    let outbox = Outbox::new();
    let stop = AtomicBool::new(false);
    let size = 1 << 20;
    for _ in 0..OUTBOX_BYTES / size {
        outbox.put(vec![1; size]).unwrap();
    }
    // Full for ordinary frames; a released frame, which the guest may have been told
    // arrived, is still queued, after what waits.
    outbox.put(vec![2; MIN_FRAME_BYTES]).unwrap();
    outbox.put_released(vec![3; 1000]).unwrap();
    for _ in 0..(RELEASED_BYTES - OUTBOX_BYTES) / size - 1 {
        outbox.put_released(vec![4; size]).unwrap();
    }
    // Past its own bound, a released frame is dropped too.
    outbox.put_released(vec![5; size]).unwrap();
    let mut taken = Vec::new();
    loop {
        let waiting = !outbox.queue.lock().unwrap().frames.is_empty();
        if !waiting {
            break;
        }
        taken.push(outbox.take(&stop).unwrap().unwrap()[0]);
    }
    let fills = OUTBOX_BYTES / size;
    assert_eq!(&taken[..fills], vec![1; fills].as_slice());
    assert_eq!(taken[fills], 3);
    assert!(taken[fills + 1..].iter().all(|first| *first == 4));
    assert!(!taken.contains(&2) && !taken.contains(&5));
}

/// A stand-in for QEMU's four socket servers.
#[cfg(windows)]
mod fake_qemu {
    use std::ptr::null_mut;

    use windows_sys::Win32::Networking::WinSock::{
        accept, bind, closesocket, listen, recv, send, setsockopt, socket, WSAStartup, AF_UNIX,
        INVALID_SOCKET, SOCKADDR, SOCKADDR_UN, SOCKET, SOCK_STREAM, SOL_SOCKET, SO_RCVTIMEO,
        SO_SNDTIMEO, WSADATA,
    };

    pub struct Listener(SOCKET);
    pub struct Peer(SOCKET);

    impl Listener {
        pub fn bind(path: &str) -> Self {
            let mut address = SOCKADDR_UN {
                sun_family: AF_UNIX,
                ..SOCKADDR_UN::default()
            };
            for (slot, byte) in address.sun_path.iter_mut().zip(path.as_bytes()) {
                *slot = i8::from_ne_bytes([*byte]);
            }
            let size = i32::try_from(std::mem::size_of::<SOCKADDR_UN>()).unwrap();
            // SAFETY: Winsock calls on a socket owned here; `address` and `data` are live.
            unsafe {
                let mut data = WSADATA::default();
                assert_eq!(WSAStartup(0x0202, &mut data), 0);
                let raw = socket(i32::from(AF_UNIX), SOCK_STREAM, 0);
                assert_ne!(raw, INVALID_SOCKET);
                assert_eq!(bind(raw, (&address as *const SOCKADDR_UN).cast::<SOCKADDR>(), size), 0);
                assert_eq!(listen(raw, 1), 0);
                Self(raw)
            }
        }

        pub fn accept(&self) -> Peer {
            // SAFETY: accept on the owned listening socket; then a live u32 option value.
            unsafe {
                let raw = accept(self.0, null_mut(), null_mut());
                assert_ne!(raw, INVALID_SOCKET);
                let timeout: u32 = 5000;
                for option in [SO_RCVTIMEO, SO_SNDTIMEO] {
                    setsockopt(raw, SOL_SOCKET, option, (&timeout as *const u32).cast(), 4);
                }
                Peer(raw)
            }
        }
    }

    impl Peer {
        pub fn send(&self, bytes: &[u8]) {
            let length = i32::try_from(bytes.len()).unwrap();
            // SAFETY: `bytes` is live and readable for `length` bytes.
            assert_eq!(unsafe { send(self.0, bytes.as_ptr(), length, 0) }, length);
        }

        /// Up to `buffer.len()` bytes; 0 at the end of the stream; negative on a timeout.
        pub fn receive(&self, buffer: &mut [u8]) -> i32 {
            let length = i32::try_from(buffer.len()).unwrap();
            // SAFETY: `buffer` is live and writable for `length` bytes.
            unsafe { recv(self.0, buffer.as_mut_ptr(), length, 0) }
        }
    }

    impl Drop for Listener {
        fn drop(&mut self) {
            // SAFETY: owned here and closed once.
            unsafe { closesocket(self.0) };
        }
    }

    impl Drop for Peer {
        fn drop(&mut self) {
            // SAFETY: owned here and closed once.
            unsafe { closesocket(self.0) };
        }
    }
}

#[cfg(unix)]
mod fake_qemu {
    use std::io::{Read, Write};
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::time::Duration;

    pub struct Listener(UnixListener);
    pub struct Peer(std::cell::RefCell<UnixStream>);

    impl Listener {
        pub fn bind(path: &str) -> Self {
            Self(UnixListener::bind(path).unwrap())
        }

        pub fn accept(&self) -> Peer {
            let (stream, _) = self.0.accept().unwrap();
            stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            stream.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
            Peer(std::cell::RefCell::new(stream))
        }
    }

    impl Peer {
        pub fn send(&self, bytes: &[u8]) {
            self.0.borrow_mut().write_all(bytes).unwrap();
        }

        pub fn receive(&self, buffer: &mut [u8]) -> i32 {
            match self.0.borrow_mut().read(buffer) {
                Ok(count) => i32::try_from(count).unwrap(),
                Err(_) => -1,
            }
        }
    }
}

#[cfg(any(windows, unix))]
fn send_frame(peer: &fake_qemu::Peer, frame: &[u8]) {
    peer.send(&u32::try_from(frame.len()).unwrap().to_be_bytes());
    peer.send(frame);
}

#[cfg(any(windows, unix))]
fn receive_frame(peer: &fake_qemu::Peer) -> Vec<u8> {
    let exact = |count: usize| {
        let mut bytes = vec![0u8; count];
        let mut filled = 0;
        while filled < count {
            let got = peer.receive(&mut bytes[filled..]);
            assert!(got > 0, "the filter sent nothing more ({got})");
            filled += usize::try_from(got).unwrap();
        }
        bytes
    };
    let length = exact(4);
    exact(usize::try_from(u32::from_be_bytes(length.try_into().unwrap())).unwrap())
}

#[cfg(any(windows, unix))]
fn socket_paths(directory: &Path) -> [HostPath; 4] {
    use crate::sandbox::qemu::{PathStyle, NETWORK_SOCKET_NAMES};
    let style = if cfg!(windows) { PathStyle::Windows } else { PathStyle::Unix };
    NETWORK_SOCKET_NAMES.map(|name| HostPath::new(style, directory.join(name).to_str().unwrap()).unwrap())
}

#[cfg(any(windows, unix))]
fn no_addresses_of_its_own() -> Result<HashSet<[u8; 4]>, String> {
    Ok(HashSet::from([[127, 0, 0, 1]]))
}

/// The filter between the sockets QEMU serves: it forwards what the policy allows, answers
/// the guest itself, passes the user network's frames back, checks who serves the sockets
/// and closes them when dropped.
#[cfg(any(windows, unix))]
#[test]
fn the_filter_runs_between_the_sockets_qemu_serves() {
    let directory = tempfile::tempdir().unwrap();
    let paths = socket_paths(directory.path());
    let listeners: Vec<fake_qemu::Listener> = paths.iter().map(|path| fake_qemu::Listener::bind(path.as_str())).collect();
    let refused = NetworkFilter::start_with(&targets(), &paths, std::process::id().wrapping_add(1), no_addresses_of_its_own)
        .expect_err("a socket served by another process is refused");
    assert!(refused.contains("not by QEMU"), "{refused}");
    // That attempt connected to the first socket: take it, so the real start gets its own.
    let stale = listeners[0].accept();
    drop(stale);
    let filter = NetworkFilter::start_with(&targets(), &paths, std::process::id(), no_addresses_of_its_own).unwrap();
    let [from_guest, to_network, from_network, to_guest] = [0, 1, 2, 3].map(|index| listeners[index].accept());
    // Allowed: on to the user network unchanged.
    let allowed = tcp(STAGING, 443, SYN);
    send_frame(&from_guest, &allowed);
    assert_eq!(receive_frame(&to_network), allowed);
    // A DNS question: answered back to the guest, never sent on.
    send_frame(&from_guest, &udp(RESOLVER, 53, &dns_query(5, "staging.mycompany.com", 1)));
    let (reply, _) = dns_of(&receive_frame(&to_guest));
    assert_eq!((rcode(&reply), answer_count(&reply)), (0, 1));
    // Refused: the guest hears so; the next allowed frame is the next the network sees.
    let blocked = tcp(GATEWAY, 8080, SYN);
    send_frame(&from_guest, &blocked);
    assert_prohibited(Verdict::Answer(receive_frame(&to_guest)), &blocked);
    let next = tcp(LAN_SERVER, 8080, SYN);
    send_frame(&from_guest, &next);
    assert_eq!(receive_frame(&to_network), next);
    // The user network's answers reach the guest.
    let back = ipv4_frame(STAGING, GUEST, TCP, &[0u8; 20]);
    send_frame(&from_network, &back);
    assert_eq!(receive_frame(&to_guest), back);
    assert!(!filter.stopped());
    // Dropped with its VM: the sockets close, so the card reaches nothing.
    drop(filter);
    let mut byte = [0u8; 1];
    for peer in [&from_guest, &to_network, &from_network, &to_guest] {
        assert_eq!(peer.receive(&mut byte), 0);
    }
}

/// Traffic both ways at once, sent as QEMU sends it: QEMU's main loop sends until the host
/// has read everything, and only then reads what the host sent it. The filter reads on while
/// its own sends wait, so neither side waits for the other, the card keeps going and every
/// frame arrives, in order.
#[cfg(any(windows, unix))]
#[test]
fn traffic_both_ways_at_once_never_stops_the_card() {
    let directory = tempfile::tempdir().unwrap();
    let paths = socket_paths(directory.path());
    let listeners: Vec<fake_qemu::Listener> = paths.iter().map(|path| fake_qemu::Listener::bind(path.as_str())).collect();
    let filter = NetworkFilter::start_with(&targets(), &paths, std::process::id(), no_addresses_of_its_own).unwrap();
    let [from_guest, to_network, from_network, to_guest] = [0, 1, 2, 3].map(|index| listeners[index].accept());
    // Far more than the sockets hold, and less than an outbox, so nothing may be dropped. To
    // an address named itself, whose bytes go on as they come.
    const FRAMES: u16 = 1500;
    let segment = |number: u16| {
        let mut segment = vec![0u8; 20 + 1400];
        segment[2..4].copy_from_slice(&8080u16.to_be_bytes());
        segment[4..6].copy_from_slice(&number.to_be_bytes());
        segment[12] = 0x50;
        segment[13] = ACK;
        segment
    };
    let uploads: Vec<Vec<u8>> = (0..FRAMES).map(|number| ipv4_frame(GUEST, LAN_SERVER, TCP, &segment(number))).collect();
    let downloads: Vec<Vec<u8>> = (0..FRAMES).map(|number| ipv4_frame(LAN_SERVER, GUEST, TCP, &segment(number))).collect();
    assert_eq!(judge(&mut Policy::new(&targets()), &uploads[0]), Verdict::Forward);
    assert!(usize::from(FRAMES) * (4 + uploads[0].len()) < OUTBOX_BYTES);
    let sending = [(from_guest, uploads.clone()), (from_network, downloads.clone())].map(|(peer, frames)| {
        std::thread::spawn(move || {
            for frame in &frames {
                send_frame(&peer, frame);
            }
            peer
        })
    });
    // Only once both have been sent whole does the test read, as QEMU would.
    let _open = sending.map(|thread| thread.join().expect("a send waited for the host to send first"));
    for (peer, frames) in [(&to_network, &uploads), (&to_guest, &downloads)] {
        for frame in frames {
            assert_eq!(&receive_frame(peer), frame);
        }
    }
    assert!(!filter.stopped());
}

/// A frame of an impossible size is a broken channel: the filter stops and closes its
/// sockets rather than guess where the next frame starts.
#[cfg(any(windows, unix))]
#[test]
fn a_broken_frame_stream_stops_the_filter_closed() {
    let directory = tempfile::tempdir().unwrap();
    let paths = socket_paths(directory.path());
    let listeners: Vec<fake_qemu::Listener> = paths.iter().map(|path| fake_qemu::Listener::bind(path.as_str())).collect();
    let filter = NetworkFilter::start_with(&Reach::PublicInternet, &paths, std::process::id(), no_addresses_of_its_own).unwrap();
    let peers = [0, 1, 2, 3].map(|index| listeners[index].accept());
    peers[0].send(&1u32.to_be_bytes());
    let deadline = Instant::now() + Duration::from_secs(5);
    while !filter.stopped() {
        assert!(Instant::now() < deadline, "the filter kept running on a broken stream");
        std::thread::sleep(Duration::from_millis(20));
    }
    drop(filter);
    let mut byte = [0u8; 1];
    assert_eq!(peers[1].receive(&mut byte), 0);
    assert_eq!(peers[3].receive(&mut byte), 0);
}

/// A TCP segment from `source` to `destination` (address and port) with its checksums, as
/// the guest's stack or QEMU's user network sends it.
#[cfg(any(windows, unix))]
fn checked_tcp(source: ([u8; 4], u16), destination: ([u8; 4], u16), sequence: u32, acknowledgement: u32, flags: u8, payload: &[u8]) -> Vec<u8> {
    let mut segment = vec![0u8; 20];
    segment[0..2].copy_from_slice(&source.1.to_be_bytes());
    segment[2..4].copy_from_slice(&destination.1.to_be_bytes());
    segment[4..8].copy_from_slice(&sequence.to_be_bytes());
    segment[8..12].copy_from_slice(&acknowledgement.to_be_bytes());
    segment[12] = 0x50;
    segment[13] = flags;
    segment[14..16].copy_from_slice(&65535u16.to_be_bytes());
    segment.extend_from_slice(payload);
    let length = u16::try_from(segment.len()).unwrap().to_be_bytes();
    let sum = checksum(&[&source.0[..], &destination.0[..], &[0, TCP][..], &length[..], &segment[..]]);
    segment[16..18].copy_from_slice(&sum.to_be_bytes());
    let mut frame = ipv4_frame(source.0, destination.0, TCP, &segment);
    let header = checksum(&[&frame[14..34]]);
    frame[24..26].copy_from_slice(&header.to_be_bytes());
    frame
}

/// A TLS ClientHello asking for `name`, in one record.
#[cfg(any(windows, unix))]
fn client_hello(name: &str) -> Vec<u8> {
    let mut server_name = u16::try_from(name.len() + 3).unwrap().to_be_bytes().to_vec();
    server_name.push(0);
    server_name.extend_from_slice(&u16::try_from(name.len()).unwrap().to_be_bytes());
    server_name.extend_from_slice(name.as_bytes());
    let mut extensions = vec![0, 0];
    extensions.extend_from_slice(&u16::try_from(server_name.len()).unwrap().to_be_bytes());
    extensions.extend_from_slice(&server_name);
    let mut body = vec![3, 3];
    body.extend_from_slice(&[1; 32]);
    body.extend_from_slice(&[0, 0, 2, 0x13, 0x01, 1, 0]);
    body.extend_from_slice(&u16::try_from(extensions.len()).unwrap().to_be_bytes());
    body.extend_from_slice(&extensions);
    let mut message = vec![1, 0];
    message.extend_from_slice(&u16::try_from(body.len()).unwrap().to_be_bytes());
    message.extend_from_slice(&body);
    let mut record = vec![0x16, 3, 1];
    record.extend_from_slice(&u16::try_from(message.len()).unwrap().to_be_bytes());
    record.extend_from_slice(&message);
    record
}

/// A connection to a host named by its name, through the filter between the sockets QEMU
/// serves: the handshake goes on, the user network's SYN-ACK is noted on its way back, the
/// ClientHello naming the host goes on, and then traffic both ways at once keeps going;
/// another connection naming another site there is reset on both sides.
#[cfg(any(windows, unix))]
#[test]
fn a_connection_held_by_name_runs_between_the_sockets_both_ways() {
    const ISN: u32 = 0x7fff_fff0;
    const SERVER_ISN: u32 = 1000;
    let directory = tempfile::tempdir().unwrap();
    let paths = socket_paths(directory.path());
    let listeners: Vec<fake_qemu::Listener> = paths.iter().map(|path| fake_qemu::Listener::bind(path.as_str())).collect();
    let filter = NetworkFilter::start_with(&targets(), &paths, std::process::id(), no_addresses_of_its_own).unwrap();
    let [from_guest, to_network, from_network, to_guest] = [0, 1, 2, 3].map(|index| listeners[index].accept());
    let server = (STAGING, 443);
    let handshake = |port: u16| {
        let guest = (GUEST, port);
        let syn = checked_tcp(guest, server, ISN, 0, SYN, b"");
        send_frame(&from_guest, &syn);
        assert_eq!(receive_frame(&to_network), syn);
        let syn_ack = checked_tcp(server, guest, SERVER_ISN, ISN.wrapping_add(1), SYN | ACK, b"");
        send_frame(&from_network, &syn_ack);
        assert_eq!(receive_frame(&to_guest), syn_ack);
        let ack = checked_tcp(guest, server, ISN.wrapping_add(1), SERVER_ISN + 1, ACK, b"");
        send_frame(&from_guest, &ack);
        assert_eq!(receive_frame(&to_network), ack);
        guest
    };
    let guest = handshake(40000);
    let hello = client_hello("staging.mycompany.com");
    let first = checked_tcp(guest, server, ISN.wrapping_add(1), SERVER_ISN + 1, ACK, &hello);
    send_frame(&from_guest, &first);
    assert_eq!(receive_frame(&to_network), first);
    // Far more than the sockets hold both ways, in stream order from the guest.
    const FRAMES: u32 = 1500;
    let mut position = ISN.wrapping_add(1).wrapping_add(u32::try_from(hello.len()).unwrap());
    let mut uploads = Vec::new();
    for number in 0..FRAMES {
        let payload = vec![u8::try_from(number % 251).unwrap(); 1400];
        uploads.push(checked_tcp(guest, server, position, SERVER_ISN + 1, ACK, &payload));
        position = position.wrapping_add(1400);
    }
    let downloads: Vec<Vec<u8>> = (0..FRAMES)
        .map(|number| checked_tcp(server, guest, SERVER_ISN + 1 + number * 1400, ISN, ACK, &[7; 1400]))
        .collect();
    let sending = [(from_guest, uploads.clone()), (from_network, downloads.clone())].map(|(peer, frames)| {
        std::thread::spawn(move || {
            for frame in &frames {
                send_frame(&peer, frame);
            }
            peer
        })
    });
    let [from_guest, from_network] = sending.map(|thread| thread.join().expect("a send waited for the host to send first"));
    for (peer, frames) in [(&to_network, &uploads), (&to_guest, &downloads)] {
        for frame in frames {
            assert_eq!(&receive_frame(peer), frame);
        }
    }
    // Another connection asks for another site at the same address: reset both ways.
    let send_and_check = |port: u16| {
        let guest = (GUEST, port);
        let syn = checked_tcp(guest, server, ISN, 0, SYN, b"");
        send_frame(&from_guest, &syn);
        assert_eq!(receive_frame(&to_network), syn);
        guest
    };
    let other = send_and_check(40001);
    let syn_ack = checked_tcp(server, other, SERVER_ISN, ISN.wrapping_add(1), SYN | ACK, b"");
    send_frame(&from_network, &syn_ack);
    assert_eq!(receive_frame(&to_guest), syn_ack);
    let refused = checked_tcp(other, server, ISN.wrapping_add(1), SERVER_ISN + 1, ACK, &client_hello("other.example"));
    send_frame(&from_guest, &refused);
    let to_the_guest = receive_frame(&to_guest);
    assert_eq!((&to_the_guest[26..30], &to_the_guest[30..34], to_the_guest[47]), (&STAGING[..], &GUEST[..], 0x14));
    let onward = receive_frame(&to_network);
    assert_eq!((&onward[26..30], &onward[30..34], onward[47]), (&GUEST[..], &STAGING[..], 0x04));
    assert_eq!(u32::from_be_bytes(onward[38..42].try_into().unwrap()), ISN.wrapping_add(1));
    assert!(!filter.stopped());
}
