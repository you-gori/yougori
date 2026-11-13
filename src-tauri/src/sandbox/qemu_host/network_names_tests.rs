//! The site each connection to an address held by name asks for: the ClientHello's server
//! name, each HTTP request's Host, another protocol's first line, read strictly and in stream
//! order, with refused connections reset on both sides and nothing let through for a
//! connection the user network did not open for exactly its SYN.

use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use super::super::{Policy, Reach, Verdict};
use super::*;
use crate::sandbox::backend::NetworkTarget;

const GUEST: [u8; 4] = [10, 0, 2, 15];
const GUEST_MAC: [u8; 6] = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];
const GATEWAY_MAC: [u8; 6] = [0x52, 0x55, 0x0a, 0x00, 0x02, 0x02];
/// A CDN address serving staging.mycompany.com and any number of other sites.
const CDN: [u8; 4] = [104, 21, 7, 9];
/// A server named by its address.
const NAMED: [u8; 4] = [93, 184, 216, 34];
const NAME: &str = "staging.mycompany.com";
const ISN: u32 = 0xffff_fff0;
const SERVER_ISN: u32 = 0x1000;

fn target(host: &str, addresses: &[[u8; 4]], ports: &[u16]) -> NetworkTarget {
    NetworkTarget {
        host: host.into(),
        addresses: addresses.iter().map(|octets| Ipv4Addr::from(*octets)).collect(),
        ports: ports.to_vec(),
    }
}

fn reach() -> Reach {
    Reach::Targets(vec![
        target(NAME, &[CDN], &[443, 80]),
        target("api.mycompany.com", &[CDN], &[8443]),
        target("every.mycompany.com", &[[104, 21, 7, 10]], &[]),
        target("93.184.216.34", &[NAMED], &[443]),
    ])
}

fn no_addresses_of_its_own() -> Result<HashSet<[u8; 4]>, String> {
    Ok(HashSet::from([[127, 0, 0, 1]]))
}

/// An Ethernet frame with an IPv4 packet, its header checksum filled in.
fn ipv4(macs: ([u8; 6], [u8; 6]), source: [u8; 4], destination: [u8; 4], transport: &[u8]) -> Vec<u8> {
    let mut frame = Vec::new();
    frame.extend_from_slice(&macs.0);
    frame.extend_from_slice(&macs.1);
    frame.extend_from_slice(&[0x08, 0x00]);
    let mut header = [0u8; 20];
    header[0] = 0x45;
    header[2..4].copy_from_slice(&u16::try_from(20 + transport.len()).unwrap().to_be_bytes());
    // Don't fragment, as guests and the filter send.
    header[6] = 0x40;
    header[8] = 64;
    header[9] = TCP;
    header[12..16].copy_from_slice(&source);
    header[16..20].copy_from_slice(&destination);
    let sum = checksum(&[&header[..]]);
    header[10..12].copy_from_slice(&sum.to_be_bytes());
    frame.extend_from_slice(&header);
    frame.extend_from_slice(transport);
    frame
}

/// The first window the user network offers in these tests' SYN-ACKs.
const FIRST_WINDOW: u16 = 64240;

/// A TCP segment between two addresses and ports, its checksum filled in.
fn tcp(source: ([u8; 4], u16), destination: ([u8; 4], u16), sequence: u32, acknowledgement: u32, flags: u8, payload: &[u8]) -> Vec<u8> {
    tcp_with(source, destination, sequence, acknowledgement, flags, FIRST_WINDOW, &[], payload)
}

/// A TCP segment offering `window`, with `options` (whole words), its checksum filled in.
#[allow(clippy::too_many_arguments)]
fn tcp_with(
    source: ([u8; 4], u16),
    destination: ([u8; 4], u16),
    sequence: u32,
    acknowledgement: u32,
    flags: u8,
    window: u16,
    options: &[u8],
    payload: &[u8],
) -> Vec<u8> {
    let mut segment = vec![0u8; 20];
    segment[0..2].copy_from_slice(&source.1.to_be_bytes());
    segment[2..4].copy_from_slice(&destination.1.to_be_bytes());
    segment[4..8].copy_from_slice(&sequence.to_be_bytes());
    segment[8..12].copy_from_slice(&acknowledgement.to_be_bytes());
    segment[12] = u8::try_from((20 + options.len()) / 4).unwrap() << 4;
    segment[13] = flags;
    segment[14..16].copy_from_slice(&window.to_be_bytes());
    segment.extend_from_slice(options);
    segment.extend_from_slice(payload);
    let length = u16::try_from(segment.len()).unwrap().to_be_bytes();
    let sum = checksum(&[&source.0[..], &destination.0[..], &[0, TCP][..], &length[..], &segment[..]]);
    segment[16..18].copy_from_slice(&sum.to_be_bytes());
    let macs = if source.0 == GUEST { (GATEWAY_MAC, GUEST_MAC) } else { (GUEST_MAC, GATEWAY_MAC) };
    ipv4(macs, source.0, destination.0, &segment)
}

/// A guest connection driven through a policy as QEMU's user network would see it.
struct Client {
    port: u16,
    server: ([u8; 4], u16),
    /// The next sequence number the guest sends, and what it acknowledges.
    sequence: u32,
    acknowledgement: u32,
    now: Instant,
}

impl Client {
    /// Opens a connection: the SYN, the user network's SYN-ACK (noted on the way back) and
    /// the handshake's ACK, each let through.
    fn open(policy: &mut Policy, server: [u8; 4], server_port: u16, port: u16) -> Self {
        let mut client = Self {
            port,
            server: (server, server_port),
            sequence: ISN,
            acknowledgement: 0,
            now: Instant::now(),
        };
        assert_eq!(client.send(policy, SYN, b""), Verdict::Forward, "the SYN goes on");
        client.sequence = ISN.wrapping_add(1);
        client.answered(policy, ISN.wrapping_add(1));
        assert_eq!(client.send(policy, ACK, b""), Verdict::Forward, "the handshake's ACK goes on");
        client
    }

    /// The user network answers a SYN that started at `start`.
    fn answered(&mut self, policy: &Policy, start: u32) {
        let syn_ack = tcp(self.server, (GUEST, self.port), SERVER_ISN, start, SYN | ACK, b"");
        policy.handshakes().note(&syn_ack, self.now + Duration::from_millis(1));
        self.acknowledgement = SERVER_ISN.wrapping_add(1);
    }

    fn frame(&self, sequence: u32, flags: u8, payload: &[u8]) -> Vec<u8> {
        tcp((GUEST, self.port), self.server, sequence, self.acknowledgement, flags, payload)
    }

    /// Sends `payload` next in the stream.
    fn send(&mut self, policy: &mut Policy, flags: u8, payload: &[u8]) -> Verdict {
        let frame = self.frame(self.sequence, flags, payload);
        self.sequence = self.sequence.wrapping_add(u32::try_from(payload.len()).unwrap());
        self.now += Duration::from_millis(2);
        policy.from_guest(&frame, self.now, &mut no_addresses_of_its_own)
    }

    /// Sends `payload` at `offset` bytes into the stream (again, or ahead).
    fn send_at(&mut self, policy: &mut Policy, offset: u32, flags: u8, payload: &[u8]) -> Verdict {
        let frame = self.frame(ISN.wrapping_add(1).wrapping_add(offset), flags, payload);
        self.now += Duration::from_millis(2);
        policy.from_guest(&frame, self.now, &mut no_addresses_of_its_own)
    }
}

/// A TLS ClientHello asking for `name` (none: no server_name extension), with `extensions`
/// after it and padding to `padding` bytes, in records of at most `record` bytes.
fn hello_with(name: Option<&str>, extensions: &[(u16, Vec<u8>)], padding: usize, record: usize) -> Vec<u8> {
    let mut listed: Vec<(u16, Vec<u8>)> = Vec::new();
    if let Some(name) = name {
        let mut data = Vec::new();
        data.extend_from_slice(&u16::try_from(name.len() + 3).unwrap().to_be_bytes());
        data.push(0);
        data.extend_from_slice(&u16::try_from(name.len()).unwrap().to_be_bytes());
        data.extend_from_slice(name.as_bytes());
        listed.push((0, data));
    }
    listed.extend(extensions.iter().cloned());
    listed.push((21, vec![0; padding]));
    let mut body = vec![0x03, 0x03];
    body.extend_from_slice(&[7; 32]);
    body.push(32);
    body.extend_from_slice(&[9; 32]);
    body.extend_from_slice(&[0, 4, 0x13, 0x01, 0x13, 0x02, 1, 0]);
    let mut all = Vec::new();
    for (kind, data) in &listed {
        all.extend_from_slice(&kind.to_be_bytes());
        all.extend_from_slice(&u16::try_from(data.len()).unwrap().to_be_bytes());
        all.extend_from_slice(data);
    }
    body.extend_from_slice(&u16::try_from(all.len()).unwrap().to_be_bytes());
    body.extend_from_slice(&all);
    let mut message = vec![1];
    message.extend_from_slice(&u32::try_from(body.len()).unwrap().to_be_bytes()[1..]);
    message.extend_from_slice(&body);
    let mut records = Vec::new();
    for fragment in message.chunks(record) {
        records.extend_from_slice(&[0x16, 0x03, 0x01]);
        records.extend_from_slice(&u16::try_from(fragment.len()).unwrap().to_be_bytes());
        records.extend_from_slice(fragment);
    }
    records
}

fn hello(name: &str) -> Vec<u8> {
    hello_with(Some(name), &[], 16, 16384)
}

fn allowed(name: &str) -> bool {
    name == NAME
}

/// The acknowledgement the filter sends the guest for the first `bytes` of a connection's
/// held opening: from the server, at the guest's place in the server's stream, offering what
/// is left of the user network's first window.
fn acknowledgement(client: &Client, bytes: usize) -> Vec<u8> {
    let window = FIRST_WINDOW - u16::try_from(bytes).unwrap();
    let acknowledged = ISN.wrapping_add(1).wrapping_add(u32::try_from(bytes).unwrap());
    tcp_with(client.server, (GUEST, client.port), client.acknowledgement, acknowledged, ACK, window, &[], b"")
}

fn assert_reset(verdict: Verdict, client: &Client, network_sequence: Option<u32>) {
    let Verdict::Reset { guest, network } = verdict else {
        panic!("expected the connection reset, got {verdict:?}");
    };
    // To the guest, from the server's address and port, at what the guest acknowledged.
    assert_eq!(&guest[0..6], &GUEST_MAC);
    assert_eq!(checksum(&[&guest[14..34]]), 0);
    assert_eq!((&guest[26..30], &guest[30..34]), (&client.server.0[..], &GUEST[..]));
    let segment = &guest[34..];
    assert_eq!(u16::from_be_bytes([segment[0], segment[1]]), client.server.1);
    assert_eq!(u16::from_be_bytes([segment[2], segment[3]]), client.port);
    assert_eq!(u32::from_be_bytes(segment[4..8].try_into().unwrap()), client.acknowledgement);
    assert_eq!(segment[13], RST | ACK);
    let length = u16::try_from(segment.len()).unwrap().to_be_bytes();
    assert_eq!(checksum(&[&client.server.0[..], &GUEST[..], &[0, TCP][..], &length[..], segment]), 0);
    match (network, network_sequence) {
        (None, None) => {}
        (Some(network), Some(sequence)) => {
            // On to the user network, from the guest, at the next byte it expects.
            assert_eq!(&network[0..6], &GATEWAY_MAC);
            assert_eq!(checksum(&[&network[14..34]]), 0);
            assert_eq!((&network[26..30], &network[30..34]), (&GUEST[..], &client.server.0[..]));
            let segment = &network[34..];
            assert_eq!(u16::from_be_bytes([segment[0], segment[1]]), client.port);
            assert_eq!(u32::from_be_bytes(segment[4..8].try_into().unwrap()), sequence);
            assert_eq!(segment[13], RST);
            let length = u16::try_from(segment.len()).unwrap().to_be_bytes();
            assert_eq!(checksum(&[&GUEST[..], &client.server.0[..], &[0, TCP][..], &length[..], segment]), 0);
        }
        (network, expected) => panic!("network reset {network:?}, expected at {expected:?}"),
    }
}

#[test]
fn a_client_hello_is_read_for_its_server_name() {
    let found = |bytes: &[u8]| match client_hello(bytes) {
        Hello::Found { length, name } => (length, name),
        other => panic!("{other:?}"),
    };
    let whole = hello(NAME);
    assert_eq!(found(&whole), (whole.len(), Some(NAME.to_owned())));
    // In mixed case, with its final dot, in records of 40 bytes: the same name.
    let split = hello_with(Some("Staging.MyCompany.com."), &[], 16, 40);
    assert!(split.len() >= hello_with(Some("Staging.MyCompany.com."), &[], 16, 16384).len() + 3 * 5, "several records");
    assert_eq!(found(&split), (split.len(), Some(NAME.to_owned())));
    // Every prefix needs more; with the rest of the flight after it, its length is its own.
    for cut in [0, 1, 4, 5, 6, 40, split.len() - 1] {
        assert_eq!(client_hello(&split[..cut]), Hello::Need, "{cut}");
    }
    let mut flight = whole.clone();
    flight.extend_from_slice(&[0x17, 0x03, 0x03, 0, 2, 1, 2]);
    assert_eq!(found(&flight).0, whole.len());
    assert_eq!(found(&hello_with(None, &[], 16, 16384)).1, None);
}

#[test]
fn a_malformed_or_ambiguous_client_hello_is_refused() {
    let name_extension = |names: &[&str]| {
        let mut list = Vec::new();
        for name in names {
            list.push(0);
            list.extend_from_slice(&u16::try_from(name.len()).unwrap().to_be_bytes());
            list.extend_from_slice(name.as_bytes());
        }
        let mut data = u16::try_from(list.len()).unwrap().to_be_bytes().to_vec();
        data.extend_from_slice(&list);
        (0u16, data)
    };
    for bad in [
        // Two names in one extension, or two server_name extensions: servers differ.
        hello_with(None, &[name_extension(&[NAME, "other.example"])], 16, 16384),
        hello_with(Some(NAME), &[name_extension(&["other.example"])], 16, 16384),
        // A name that is no host name.
        hello_with(Some("bad_name.example"), &[], 16, 16384),
        hello_with(Some("[::1]"), &[], 16, 16384),
        hello_with(Some(""), &[], 16, 16384),
    ] {
        assert_eq!(client_hello(&bad), Hello::Refuse);
    }
    let whole = hello(NAME);
    let mut wrong_type = whole.clone();
    wrong_type[5] = 2; // a ServerHello
    let mut wrong_record = whole.clone();
    wrong_record[0] = 0x17;
    let mut empty_record = vec![0x16, 0x03, 0x01, 0, 0];
    empty_record.extend_from_slice(&whole);
    let mut short_list = whole.clone();
    // The extensions' total length one less than they are.
    let total_at = 5 + 4 + 2 + 32 + 1 + 32 + 2 + 4 + 2;
    short_list[total_at + 1] -= 1;
    let mut more_in_record = whole.clone();
    more_in_record.push(0);
    let length = u16::from_be_bytes([more_in_record[3], more_in_record[4]]) + 1;
    more_in_record[3..5].copy_from_slice(&length.to_be_bytes());
    for bad in [wrong_type, wrong_record, empty_record, short_list, more_in_record] {
        assert_eq!(client_hello(&bad), Hello::Refuse);
    }
}

#[test]
fn a_first_line_tells_http_from_other_protocols() {
    assert_eq!(opening(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"), Opening::Http);
    assert_eq!(opening(b"\r\n\r\nPOST /api HTTP/1.0\r\n"), Opening::Http);
    // Whatever a forgiving server might take as a request line is read as one.
    for line in [
        &b"get / http/1.1\r\n"[..],
        b"GET\t/\tHTTP/1.1\r\n",
        b"GET /\r\n",
        b"FOO http://other.example/ x\r\n",
        b"connect other.example:443\r\n",
        b"PRI * HTTP/2.0\r\n",
        b"\xc3\xa9t\xc3\xa9 HTTP/1.1\n",
    ] {
        assert_eq!(opening(line), Opening::Http, "{}", String::from_utf8_lossy(line));
    }
    // Other protocols name no site.
    assert_eq!(opening(b"SSH-2.0-OpenSSH_9.6\r\n"), Opening::Other { length: 21 });
    assert_eq!(opening(b"EHLO staging.mycompany.com\r\n"), Opening::Other { length: 28 });
    assert_eq!(opening(b"*2\r\n$3\r\nGET\r\n"), Opening::Other { length: 4 });
    assert_eq!(opening(b"get key\r\n"), Opening::Other { length: 9 });
    assert_eq!(opening(b"\x00\x00\x00\x08\x04\xd2\x16\x2f"), Opening::Other { length: 1 });
    assert_eq!(opening(b"\r\nAB\x01CD"), Opening::Other { length: 5 });
    // Not yet told; told never: TLS after blanks, SSL 2's ClientHello, a line too long.
    assert_eq!(opening(b"GET / HTTP/1.1"), Opening::Need);
    assert_eq!(opening(b"\r\n \t"), Opening::Need);
    assert_eq!(opening(b"\x80"), Opening::Need);
    assert_eq!(opening(b"\xc3\xa9t\xc3\xa9\x01"), Opening::Other { length: 6 });
    assert_eq!(opening(b"\r\n\x16\x03\x01\x00\x05"), Opening::Refuse);
    assert_eq!(opening(b"\x80\x2e\x01\x03\x01"), Opening::Refuse);
    assert_eq!(opening(&vec![b'a'; MAX_LINE]), Opening::Refuse);
}

fn head(bytes: &[u8]) -> Head {
    request_head(bytes, &allowed)
}

#[test]
fn an_http_request_head_must_name_a_named_host_there_or_none() {
    let request = b"GET /index.html?q=1 HTTP/1.1\r\nHost: staging.mycompany.com\r\nUser-Agent: test\r\n\r\n";
    assert_eq!(head(request), Head::Request { length: request.len(), body: Http::Head });
    for allowed_head in [
        &b"GET / HTTP/1.1\r\nHOST:  Staging.MyCompany.com.:443 \r\n\r\n"[..],
        b"POST /form HTTP/1.1\r\nHost: staging.mycompany.com\r\nContent-Length: 0\r\n\r\n",
        b"GET http://staging.mycompany.com:80/path HTTP/1.1\r\nHost: staging.mycompany.com\r\n\r\n",
        b"GET https://staging.mycompany.com/ HTTP/1.1\r\n\r\n",
        b"OPTIONS * HTTP/1.1\r\nHost: staging.mycompany.com\r\n\r\n",
        // No site named: the server's default site alone.
        b"GET / HTTP/1.0\r\n\r\n",
        b"GET / HTTP/1.1\r\nHost:\r\n\r\n",
    ] {
        assert!(matches!(head(allowed_head), Head::Request { .. }), "{}", String::from_utf8_lossy(allowed_head));
    }
    let put = b"PUT /x HTTP/1.1\r\nHost: staging.mycompany.com\r\nContent-Length: 12\r\n\r\nbody follows";
    assert_eq!(head(put), Head::Request { length: put.len() - 12, body: Http::Body(12) });
    let chunked = b"POST /x HTTP/1.1\r\nHost: staging.mycompany.com\r\nTransfer-Encoding: Chunked\r\n\r\n";
    assert_eq!(head(chunked), Head::Request { length: chunked.len(), body: Http::Size { digits: 0, value: 0, cr: false } });
    assert_eq!(head(b"\r\n\r\nGET"), Head::Blank(4));
    assert_eq!(head(b"GET / HTTP/1.1\r\nHost: staging.mycompany.com\r\n"), Head::Need);
}

#[test]
fn an_http_request_for_another_site_or_read_two_ways_is_refused() {
    for refused in [
        // Another site, by Host or by absolute address; an address instead of a name.
        &b"GET / HTTP/1.1\r\nHost: other.example\r\n\r\n"[..],
        b"GET http://other.example/ HTTP/1.1\r\nHost: staging.mycompany.com\r\n\r\n",
        b"GET http://other.example/ HTTP/1.1\r\n\r\n",
        b"GET http://staging.mycompany.com@other.example/ HTTP/1.1\r\n\r\n",
        b"GET / HTTP/1.1\r\nHost: 104.21.7.9\r\n\r\n",
        b"GET / HTTP/1.1\r\nHost: [::1]\r\n\r\n",
        // Read two ways by two servers.
        b"GET / HTTP/1.1\r\nHost: staging.mycompany.com\r\nHost: other.example\r\n\r\n",
        b"POST / HTTP/1.1\r\nHost: staging.mycompany.com\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\n",
        b"POST / HTTP/1.1\r\nHost: staging.mycompany.com\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n",
        b"POST / HTTP/1.1\r\nHost: staging.mycompany.com\r\nTransfer-Encoding: gzip, chunked\r\n\r\n",
        b"POST / HTTP/1.0\r\nHost: staging.mycompany.com\r\nTransfer-Encoding: chunked\r\n\r\n",
        b"POST / HTTP/1.1\r\nHost: staging.mycompany.com\r\nContent-Length: +5\r\n\r\n",
        b"GET / HTTP/1.1\r\nHost : other.example\r\nHost: staging.mycompany.com\r\n\r\n",
        b"GET / HTTP/1.1\r\nX: a\r\n Host: other.example\r\nHost: staging.mycompany.com\r\n\r\n",
        b"GET / HTTP/1.1\r\nHost: staging.mycompany.com\r\nX: a\x00b\r\n\r\n",
        b"GET  / HTTP/1.1\r\nHost: staging.mycompany.com\r\n\r\n",
        b"GET / HTTP/1.1 x\r\nHost: staging.mycompany.com\r\n\r\n",
        b"get / HTTP/1.1\r\nHost: staging.mycompany.com\r\n\r\n",
        b"GET / HTTP/2.0\r\nHost: staging.mycompany.com\r\n\r\n",
        b"GET x HTTP/1.1\r\nHost: staging.mycompany.com\r\n\r\n",
        b"GET * HTTP/1.1\r\nHost: staging.mycompany.com\r\n\r\n",
        // What turns the connection into something else, or a tunnel.
        b"GET / HTTP/1.1\r\nHost: staging.mycompany.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n",
        b"CONNECT other.example:443 HTTP/1.1\r\nHost: staging.mycompany.com\r\n\r\n",
        b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n",
        // Bare line ends.
        b"GET / HTTP/1.1\nHost: other.example\n\n",
        b"GET / HTTP/1.1\r\nHost: staging.mycompany.com\rX: y\r\n\r\n",
    ] {
        assert_eq!(head(refused), Head::Refuse, "{}", String::from_utf8_lossy(refused));
    }
    let mut long = b"GET / HTTP/1.1\r\nX: ".to_vec();
    long.resize(MAX_HEAD, b'a');
    assert_eq!(head(&long), Head::Refuse);
}

#[test]
fn chunked_framing_is_strict() {
    let mut state = Http::Size { digits: 0, value: 0, cr: false };
    for &byte in b"1A\r\n" {
        state = chunk_framing(state, byte).unwrap();
    }
    assert_eq!(state, Http::Data(26));
    for (bytes, fails_at) in [(&b"1;ext\r\n"[..], 1), (b" 1\r\n", 0), (b"\r\n", 0), (b"1 \r\n", 1), (b"1\rx", 2), (b"0123456789abcdef", 15)] {
        let mut state = Http::Size { digits: 0, value: 0, cr: false };
        for (index, &byte) in bytes.iter().enumerate() {
            match chunk_framing(state, byte) {
                Some(next) => state = next,
                None => {
                    assert_eq!(index, fails_at, "{}", String::from_utf8_lossy(bytes));
                    break;
                }
            }
        }
    }
    // After the last chunk, only the final CRLF: trailers are refused.
    let last = chunk_framing(chunk_framing(Http::Size { digits: 1, value: 0, cr: false }, b'\r').unwrap(), b'\n').unwrap();
    assert_eq!(last, Http::Last { cr: false });
    assert_eq!(chunk_framing(last, b'X'), None);
    assert_eq!(chunk_framing(chunk_framing(last, b'\r').unwrap(), b'\n'), Some(Http::Head));
}

#[test]
fn https_to_a_named_host_goes_on_once_its_client_hello_names_it() {
    let mut policy = Policy::new(&reach());
    let mut client = Client::open(&mut policy, CDN, 443, 40001);
    // A ClientHello of three segments (post-quantum key shares make them that big): held
    // until whole, then all of it goes on, in order.
    let whole = hello_with(Some(NAME), &[], 3000, 16384);
    let parts: Vec<&[u8]> = whole.chunks(1448).collect();
    assert_eq!(parts.len(), 3);
    let mut frames = Vec::new();
    let mut sent = 0;
    for (index, part) in parts.iter().enumerate() {
        frames.push(client.frame(client.sequence, ACK, part));
        let verdict = client.send(&mut policy, ACK, part);
        sent += part.len();
        if index < 2 {
            // Held, and acknowledged to the guest so that it sends the rest.
            assert_eq!(verdict, Verdict::Held(Some(acknowledgement(&client, sent))), "part {index}");
        } else {
            assert_eq!(verdict, Verdict::Release(frames.clone()));
        }
    }
    // Then the encrypted stream passes unread, both ways at once, a lot of it.
    for round in 0..3000u32 {
        let block = vec![u8::try_from(round % 251).unwrap(); 1448];
        assert_eq!(client.send(&mut policy, ACK, &block), Verdict::Forward, "round {round}");
    }
    assert_eq!(client.send(&mut policy, FIN | ACK, b""), Verdict::Forward);
}

#[test]
fn https_naming_another_site_or_none_is_reset_before_any_byte_leaves() {
    for (index, refused) in [
        hello("other.example"),
        hello("www.staging.mycompany.com"),
        // api.mycompany.com is named at this address, but for port 8443 alone.
        hello("api.mycompany.com"),
        hello_with(None, &[], 16, 16384),
    ]
    .into_iter()
    .enumerate()
    {
        let mut policy = Policy::new(&reach());
        let port = 40100 + u16::try_from(index).unwrap();
        let mut client = Client::open(&mut policy, CDN, 443, port);
        let verdict = client.send(&mut policy, ACK | 0x08, &refused);
        assert_reset(verdict, &client, Some(ISN.wrapping_add(1)));
        // Everything after is answered with a reset alone, and nothing goes on.
        let verdict = client.send(&mut policy, ACK, b"GET / HTTP/1.1\r\nHost: other.example\r\n\r\n");
        assert_reset(verdict, &client, None);
    }
    // The same name on the port it was named for goes on.
    let mut policy = Policy::new(&reach());
    let mut client = Client::open(&mut policy, CDN, 8443, 40200);
    assert_eq!(client.send(&mut policy, ACK, &hello("api.mycompany.com")), Verdict::Forward);
}

#[test]
fn plain_http_is_read_request_by_request() {
    let mut policy = Policy::new(&reach());
    let mut client = Client::open(&mut policy, CDN, 80, 40300);
    let first = b"GET / HTTP/1.1\r\nHost: staging.mycompany.com\r\n\r\n";
    assert_eq!(client.send(&mut policy, ACK, first), Verdict::Forward);
    // A request in two segments is held until its head is whole.
    let upload = b"POST /up HTTP/1.1\r\nHost: staging.mycompany.com\r\nContent-Length: 5000\r\n\r\n";
    let (front, back) = upload.split_at(20);
    let front_frame = client.frame(client.sequence, ACK, front);
    assert_eq!(client.send(&mut policy, ACK, front), Verdict::Held(None), "after a request went on, nothing is acknowledged");
    let back_frame = client.frame(client.sequence, ACK, back);
    assert_eq!(client.send(&mut policy, ACK, back), Verdict::Release(vec![front_frame, back_frame]));
    // Its body passes as it comes, whatever it looks like.
    for _ in 0..4 {
        assert_eq!(client.send(&mut policy, ACK, &b"GET / HTTP/1.1\r\nHost: other.example\r\n\r\n".repeat(30)[..1000]), Verdict::Forward);
    }
    // The body's end and the next request's start in one segment: held until its head ends.
    let mut joined = vec![b'z'; 1000];
    joined.extend_from_slice(b"\r\nGET /next HTTP/1.1\r\nHo");
    assert_eq!(client.send(&mut policy, ACK, &joined), Verdict::Held(None));
    assert!(matches!(client.send(&mut policy, ACK, b"st: staging.mycompany.com\r\n\r\n"), Verdict::Release(frames) if frames.len() == 2));
    // A chunked body, then a request for another site: reset at the next byte held back.
    let chunked = b"POST /c HTTP/1.1\r\nHost: staging.mycompany.com\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n";
    assert_eq!(client.send(&mut policy, ACK, chunked), Verdict::Forward);
    let sent = client.sequence;
    let verdict = client.send(&mut policy, ACK, b"GET / HTTP/1.1\r\nHost: other.example\r\n\r\n");
    assert_reset(verdict, &client, Some(sent));
}

#[test]
fn other_protocols_name_no_site_and_pass_after_their_first_line() {
    let mut policy = Policy::new(&reach());
    let mut client = Client::open(&mut policy, [104, 21, 7, 10], 22, 40400);
    assert_eq!(client.send(&mut policy, ACK, b"SSH-2.0-OpenSSH_9.6\r\n"), Verdict::Forward);
    assert_eq!(client.send(&mut policy, ACK, &[0x00, 0x00, 0x01, 0x2c, 0x0a, 0x14]), Verdict::Forward);
    assert_eq!(client.send(&mut policy, ACK, b"GET / HTTP/1.1\r\nHost: other.example\r\n\r\n"), Verdict::Forward);
}

#[test]
fn a_copy_sent_again_must_equal_what_was_read() {
    let mut policy = Policy::new(&reach());
    let mut client = Client::open(&mut policy, CDN, 80, 40500);
    let request = b"GET / HTTP/1.1\r\nHost: staging.mycompany.com\r\n\r\n";
    assert_eq!(client.send(&mut policy, ACK, request), Verdict::Forward);
    // The same bytes again (the user network may have missed them): on again.
    assert_eq!(client.send_at(&mut policy, 0, ACK, request), Verdict::Forward);
    // A copy that names another site in their place: the connection is reset.
    let changed = b"GET / HTTP/1.1\r\nHost: evil-site.example.com\r\n\r\n";
    assert_eq!(changed.len(), request.len());
    assert_reset(client.send_at(&mut policy, 0, ACK, changed), &client, Some(client.sequence));

    // While held, a copy goes nowhere; a copy with new bytes after it is held as well.
    let mut policy = Policy::new(&reach());
    let mut client = Client::open(&mut policy, CDN, 80, 40501);
    assert_eq!(client.send(&mut policy, ACK, b"GET / HTTP/1.1\r\n"), Verdict::Held(Some(acknowledgement(&client, 16))));
    assert_eq!(client.send_at(&mut policy, 0, ACK, b"GET / HTTP/1.1\r\n"), Verdict::Answer(acknowledgement(&client, 16)), "acknowledged again");
    let longer = b"GET / HTTP/1.1\r\nHost: staging";
    assert_eq!(client.send_at(&mut policy, 0, ACK, longer), Verdict::Held(Some(acknowledgement(&client, longer.len()))));
    client.sequence = ISN.wrapping_add(1).wrapping_add(u32::try_from(longer.len()).unwrap());
    assert!(matches!(client.send(&mut policy, ACK, b".mycompany.com\r\n\r\n"), Verdict::Release(frames) if frames.len() == 3));
    // A gap goes nowhere (the user network would wait for the bytes before it).
    assert_eq!(client.send_at(&mut policy, 5000, ACK, b"later"), Verdict::Drop);
}

#[test]
fn segments_the_user_network_would_drop_or_read_otherwise_go_nowhere() {
    let mut policy = Policy::new(&reach());
    let mut client = Client::open(&mut policy, CDN, 443, 40600);
    let mut bad_checksum = client.frame(client.sequence, ACK, &hello(NAME));
    let last = bad_checksum.len() - 1;
    bad_checksum[last] ^= 0xff;
    assert_eq!(policy.from_guest(&bad_checksum, client.now, &mut no_addresses_of_its_own), Verdict::Drop);
    let without_ack = client.frame(client.sequence, 0x08, &hello(NAME));
    assert_eq!(policy.from_guest(&without_ack, client.now, &mut no_addresses_of_its_own), Verdict::Drop);
    let reset_with_bytes = client.frame(client.sequence, RST | ACK, b"x");
    assert_eq!(policy.from_guest(&reset_with_bytes, client.now, &mut no_addresses_of_its_own), Verdict::Drop);
    // Urgent data would leave the server's stream: refused before the decision.
    assert_reset(client.send(&mut policy, ACK | URG, &hello(NAME)), &client, Some(ISN.wrapping_add(1)));
    // So is a bare urgent mark (it points at bytes still to come), and one for a connection
    // no longer followed goes nowhere.
    let mut policy = Policy::new(&reach());
    let mut client = Client::open(&mut policy, CDN, 80, 40603);
    assert_eq!(client.send(&mut policy, ACK, b"GET / HTTP/1.1\r\nHost: staging.mycompany.com\r\n\r\n"), Verdict::Forward);
    assert_reset(client.send(&mut policy, ACK | URG, b""), &client, Some(client.sequence));
    let stray = tcp((GUEST, 40604), (CDN, 80), 5, 9, ACK | URG, b"");
    assert_eq!(policy.from_guest(&stray, Instant::now(), &mut no_addresses_of_its_own), Verdict::Drop);
    // Once a connection is read no further, its later urgent data is its own.
    let mut client = Client::open(&mut policy, [104, 21, 7, 10], 21, 40605);
    assert_eq!(client.send(&mut policy, ACK, b"USER anonymous\r\n"), Verdict::Forward);
    assert_eq!(client.send(&mut policy, ACK | URG, b"\xff\xf4\xff\xf2ABOR\r\n"), Verdict::Forward);
    // A stream that ends before it says what it is for.
    let mut policy = Policy::new(&reach());
    let mut client = Client::open(&mut policy, CDN, 80, 40601);
    assert_eq!(client.send(&mut policy, ACK, b"GET / HTTP/1.1\r\n"), Verdict::Held(Some(acknowledgement(&client, 16))));
    assert_reset(client.send(&mut policy, ACK | FIN, b""), &client, Some(ISN.wrapping_add(1)));
    // A SYN carrying bytes goes nowhere.
    let mut policy = Policy::new(&reach());
    let syn_with_bytes = tcp((GUEST, 40602), (CDN, 80), ISN, 0, SYN, b"GET / HTTP/1.1\r\n\r\n");
    assert_eq!(policy.from_guest(&syn_with_bytes, Instant::now(), &mut no_addresses_of_its_own), Verdict::Drop);
}

#[test]
fn bytes_count_only_on_a_connection_the_user_network_opened_for_that_syn() {
    // No answer to the SYN noted: its bytes are refused.
    let mut policy = Policy::new(&reach());
    let mut client = Client {
        port: 40700,
        server: (CDN, 443),
        sequence: ISN,
        acknowledgement: SERVER_ISN.wrapping_add(1),
        now: Instant::now(),
    };
    assert_eq!(client.send(&mut policy, SYN, b""), Verdict::Forward);
    client.sequence = ISN.wrapping_add(1);
    assert_eq!(client.send(&mut policy, ACK, b""), Verdict::Forward, "no bytes: harmless");
    assert_reset(client.send(&mut policy, ACK, &hello(NAME)), &client, Some(ISN.wrapping_add(1)));

    // An answer noted before the SYN (an older connection's) does not count either.
    let mut policy = Policy::new(&reach());
    let mut client = Client {
        port: 40701,
        server: (CDN, 443),
        sequence: ISN,
        acknowledgement: 0,
        now: Instant::now(),
    };
    client.answered(&policy, ISN.wrapping_add(1));
    client.now += Duration::from_secs(1);
    assert_eq!(client.send(&mut policy, SYN, b""), Verdict::Forward);
    client.sequence = ISN.wrapping_add(1);
    assert_reset(client.send(&mut policy, ACK, &hello(NAME)), &client, Some(ISN.wrapping_add(1)));

    // A made-up SYN on a live connection starts over, and the user network (which keeps
    // the older connection) never answers it: nothing more goes on.
    let mut policy = Policy::new(&reach());
    let mut client = Client::open(&mut policy, CDN, 80, 40702);
    assert_eq!(client.send(&mut policy, ACK, b"GET / HTTP/1.1\r\nHost: staging.mycompany.com\r\n\r\n"), Verdict::Forward);
    let resynced = tcp((GUEST, 40702), (CDN, 80), client.sequence.wrapping_sub(1), 0, SYN, b"");
    assert_eq!(policy.from_guest(&resynced, client.now, &mut no_addresses_of_its_own), Verdict::Forward);
    assert!(matches!(client.send(&mut policy, ACK, &hello(NAME)), Verdict::Reset { .. }));

    // A connection never seen opening: its bytes are reset, a bare acknowledgement goes on.
    let mut policy = Policy::new(&reach());
    let stray = tcp((GUEST, 40703), (CDN, 443), 5, 9, ACK, b"data");
    assert!(matches!(policy.from_guest(&stray, Instant::now(), &mut no_addresses_of_its_own), Verdict::Reset { network: Some(_), .. }));
    let bare = tcp((GUEST, 40703), (CDN, 443), 5, 9, ACK, b"");
    assert_eq!(policy.from_guest(&bare, Instant::now(), &mut no_addresses_of_its_own), Verdict::Forward);
}

#[test]
fn an_address_named_itself_is_not_read() {
    let mut policy = Policy::new(&reach());
    // No SYN seen and no handshake noted: an address target's bytes go on as they are.
    let segment = tcp((GUEST, 40800), (NAMED, 443), 77, 5, ACK, b"anything at all");
    assert_eq!(policy.from_guest(&segment, Instant::now(), &mut no_addresses_of_its_own), Verdict::Forward);
}

#[test]
fn the_reading_has_limits() {
    // A head that never ends, and a ClientHello in too many small segments.
    let mut policy = Policy::new(&reach());
    let mut client = Client::open(&mut policy, CDN, 80, 40900);
    let mut verdict = client.send(&mut policy, ACK, b"GET / HTTP/1.1\r\n");
    while matches!(verdict, Verdict::Held(_)) {
        verdict = client.send(&mut policy, ACK, &[b"X-Padding: ".as_slice(), &[b'a'; 1000], b"\r\n"].concat());
    }
    assert!(matches!(verdict, Verdict::Reset { .. }));
    let mut policy = Policy::new(&reach());
    let mut client = Client::open(&mut policy, CDN, 443, 40901);
    let whole = hello_with(Some(NAME), &[], 2000, 16384);
    let mut verdicts = whole.chunks(10).map(|part| client.send(&mut policy, ACK, part));
    assert!(verdicts.by_ref().take(MAX_HELD_FRAMES).all(|verdict| matches!(verdict, Verdict::Held(_))));
    assert!(matches!(verdicts.next(), Some(Verdict::Reset { .. })));
}

#[test]
fn quiet_and_closed_connections_are_forgotten() {
    let mut policy = Policy::new(&reach());
    let mut closed = Client::open(&mut policy, CDN, 80, 41000);
    assert_eq!(closed.send(&mut policy, ACK | FIN, b""), Verdict::Forward);
    let mut open = Client::open(&mut policy, CDN, 80, 41001);
    assert_eq!(policy.connections.followed(), 2);
    let later = open.now + CLOSED_IDLE + SWEEP;
    open.now = later;
    assert_eq!(open.send(&mut policy, ACK, b""), Verdict::Forward);
    assert_eq!(policy.connections.followed(), 1, "the closed one is forgotten");
    open.now = later + IDLE;
    assert_eq!(open.send(&mut policy, ACK, b""), Verdict::Forward);
    assert_eq!(policy.connections.followed(), 0);
    // Forgotten, its bytes are reset rather than let through unread.
    assert!(matches!(open.send(&mut policy, ACK, b"GET / HTTP/1.1\r\nHost: other.example\r\n\r\n"), Verdict::Reset { .. }));
}

#[test]
fn a_reset_from_the_guest_ends_the_connection() {
    let mut policy = Policy::new(&reach());
    let mut client = Client::open(&mut policy, CDN, 443, 41100);
    assert_eq!(client.send(&mut policy, RST, b""), Verdict::Forward);
    assert_eq!(policy.connections.followed(), 0);
    assert!(matches!(client.send(&mut policy, ACK, &hello(NAME)), Verdict::Reset { .. }));
}

#[test]
fn a_held_opening_is_acknowledged_only_within_the_user_networks_first_window() {
    // Nagle's algorithm holds a guest's second small write until its first is acknowledged:
    // the filter acknowledges a held opening itself, offering the rest of the first window.
    let mut policy = Policy::new(&reach());
    let mut client = Client::open(&mut policy, CDN, 80, 41200);
    let Verdict::Held(Some(answer)) = client.send(&mut policy, ACK, b"GET / HTTP/1.1\r\nHo") else {
        panic!("a held opening is acknowledged");
    };
    assert_eq!(answer, acknowledgement(&client, 18));
    assert_eq!((answer[47], u16::from_be_bytes([answer[48], answer[49]])), (ACK, FIRST_WINDOW - 18));
    assert!(matches!(client.send(&mut policy, ACK, b"st: staging.mycompany.com\r\n\r\n"), Verdict::Release(frames) if frames.len() == 2));

    let first_answer = |policy: &Policy, client: &mut Client, window: u16, options: &[u8]| {
        let syn_ack = tcp_with(client.server, (GUEST, client.port), SERVER_ISN, ISN.wrapping_add(1), SYN | ACK, window, options, b"");
        policy.handshakes().note(&syn_ack, client.now + Duration::from_millis(1));
        client.acknowledgement = SERVER_ISN.wrapping_add(1);
    };
    let opened = |policy: &mut Policy, port: u16| {
        let mut client = Client { port, server: (CDN, 80), sequence: ISN, acknowledgement: 0, now: Instant::now() };
        assert_eq!(client.send(policy, SYN, b""), Verdict::Forward);
        client.sequence = ISN.wrapping_add(1);
        client
    };
    // A user network that scales its window: the window could not be told, so none is.
    let mut policy = Policy::new(&reach());
    let mut client = opened(&mut policy, 41201);
    first_answer(&policy, &mut client, FIRST_WINDOW, &[2, 4, 0x05, 0xb4, 1, 3, 3, 7]);
    assert_eq!(client.send(&mut policy, ACK, b""), Verdict::Forward);
    assert_eq!(client.send(&mut policy, ACK, b"GET / HTTP/1.1\r\n"), Verdict::Held(None));
    // A first window smaller than what is held: acknowledged up to it, then no more.
    let mut policy = Policy::new(&reach());
    let mut client = opened(&mut policy, 41202);
    first_answer(&policy, &mut client, 20, &[2, 4, 0x05, 0xb4]);
    assert_eq!(client.send(&mut policy, ACK, b""), Verdict::Forward);
    let Verdict::Held(Some(answer)) = client.send(&mut policy, ACK, b"GET / HTTP/1.1\r\n") else {
        panic!("held within the window");
    };
    assert_eq!(u16::from_be_bytes([answer[48], answer[49]]), 4);
    assert_eq!(client.send(&mut policy, ACK, b"Host: staging"), Verdict::Held(None));
}

#[test]
fn stream_positions_follow_the_sequence_numbers_across_their_wrap() {
    let mut connection = Connection::new(ISN.wrapping_add(1), Instant::now());
    assert_eq!(connection.position(ISN.wrapping_add(1)), Some(0));
    assert_eq!(connection.position(ISN), None, "before the stream's start");
    assert_eq!(connection.position(ISN.wrapping_add(100)), Some(99));
    connection.next = (1 << 32) + 10;
    assert_eq!(connection.position(ISN.wrapping_add(11)), Some((1 << 32) + 10));
    assert_eq!(connection.position(ISN.wrapping_add(1)), Some(1 << 32));
}
