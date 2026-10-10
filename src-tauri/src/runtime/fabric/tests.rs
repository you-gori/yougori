use super::*;

fn peer(fabric: &Fabric, id: &str) -> mpsc::Receiver<Vec<u8>> {
    let (tx, rx) = mpsc::channel(128);
    fabric.0.lock().unwrap().peers.insert(
        id.into(),
        Peer {
            gateway_access: None,
            gateway_listener: None,
            file_context: None,
            files: None,
            identity: address(id),
            generation: id.into(),
            tx,
        },
    );
    rx
}
fn tcp(source: &str, target: &str, sport: u16, dport: u16, flags: u8) -> Vec<u8> {
    let mut p = vec![0; 54];
    p[..6].copy_from_slice(&address(target).1);
    p[6..12].copy_from_slice(&address(source).1);
    p[12..14].copy_from_slice(&[8, 0]);
    p[14] = 0x45;
    p[16..18].copy_from_slice(&40u16.to_be_bytes());
    p[23] = 6;
    p[26..30].copy_from_slice(&address(source).0);
    p[30..34].copy_from_slice(&address(target).0);
    p[34..36].copy_from_slice(&sport.to_be_bytes());
    p[36..38].copy_from_slice(&dport.to_be_bytes());
    p[46] = 0x50;
    p[47] = flags;
    p
}
#[test]
fn fabric_port_rules_direction_replies_and_revocation() {
    let fabric = Fabric::default();
    let mut a = peer(&fabric, "a");
    let mut b = peer(&fabric, "b");
    let mut c = peer(&fabric, "c");
    fabric.route("a", &tcp("a", "b", 40000, 22, 2));
    assert!(b.try_recv().is_err());
    fabric
        .apply(
            "ab",
            "a",
            "b",
            &ConnectionDirection::OneWay,
            &[PermissionKind::Ports],
            &[22],
        )
        .unwrap();
    fabric.route("a", &tcp("a", "b", 40000, 80, 2));
    assert!(b.try_recv().is_err());
    fabric.route("b", &tcp("b", "a", 40000, 22, 2));
    assert!(a.try_recv().is_err());
    let request = tcp("a", "b", 40000, 22, 2);
    fabric.route("a", &request);
    assert_eq!(b.try_recv().unwrap(), request);
    fabric.route("b", &tcp("b", "a", 22, 40000, 0x12));
    assert!(a.try_recv().is_ok());
    fabric.route("b", &tcp("b", "a", 22, 40000, 2));
    assert!(a.try_recv().is_err());
    fabric.route("a", &tcp("a", "c", 40000, 22, 2));
    assert!(c.try_recv().is_err());
    fabric
        .apply(
            "ab",
            "a",
            "b",
            &ConnectionDirection::OneWay,
            &[PermissionKind::Ports],
            &[22],
        )
        .unwrap();
    fabric.route("b", &tcp("b", "a", 22, 40000, 0x10));
    assert!(a.try_recv().is_ok());
    fabric.remove("ab");
    fabric.route("b", &tcp("b", "a", 22, 40000, 0x10));
    assert!(a.try_recv().is_err());
}
#[test]
fn fabric_rejects_spoofing_fragments_ipv6_and_ungranted_directions() {
    let fabric = Fabric::default();
    let _a = peer(&fabric, "a");
    let mut b = peer(&fabric, "b");
    fabric
        .apply(
            "ab",
            "a",
            "b",
            &ConnectionDirection::Bidirectional,
            &[PermissionKind::Network],
            &[],
        )
        .unwrap();
    let valid = tcp("a", "b", 33333, 45678, 2);
    for index in [6, 26, 30] {
        let mut p = valid.clone();
        p[index] ^= 1;
        fabric.route("a", &p);
        assert!(b.try_recv().is_err());
    }
    let mut p = valid.clone();
    p[20] = 0x20;
    fabric.route("a", &p);
    assert!(b.try_recv().is_err());
    p[12] = 0x86;
    p[13] = 0xdd;
    fabric.route("a", &p);
    assert!(b.try_recv().is_err());
    fabric.route("a", &valid);
    assert!(b.try_recv().is_ok());
}
#[test]
fn fabric_dhcp_has_private_address_but_no_gateway_or_dns() {
    let (ip, mac) = address("windows");
    let mut p = vec![0; 14 + 20 + 8 + 244];
    p[12..14].copy_from_slice(&[8, 0]);
    p[14] = 0x45;
    let size = (p.len() - 14) as u16;
    p[16..18].copy_from_slice(&size.to_be_bytes());
    p[23] = 17;
    p[34..36].copy_from_slice(&68u16.to_be_bytes());
    p[36..38].copy_from_slice(&67u16.to_be_bytes());
    p[42..45].copy_from_slice(&[1, 1, 6]);
    p[70..76].copy_from_slice(&mac);
    p[278..282].copy_from_slice(&[99, 130, 83, 99]);
    p[282..286].copy_from_slice(&[53, 1, 1, 255]);
    let reply = dhcp(&p, ip, mac).unwrap();
    assert_eq!(&reply[58..62], &ip);
    assert_eq!(checksum(&reply[14..34]), 0);
    let options = &reply[282..];
    let mut pos = 0;
    while options[pos] != 255 {
        assert!(![3, 6].contains(&options[pos]));
        pos += 2 + options[pos + 1] as usize;
    }
    p[70] ^= 1;
    assert!(dhcp(&p, ip, mac).is_none());
}
#[test]
fn fabric_arp_only_reaches_a_granted_peer() {
    let fabric = Fabric::default();
    let _a = peer(&fabric, "a");
    let mut b = peer(&fabric, "b");
    let mut p = vec![0; 42];
    p[..6].fill(255);
    p[6..12].copy_from_slice(&address("a").1);
    p[12..14].copy_from_slice(&[8, 6]);
    p[14..22].copy_from_slice(&[0, 1, 8, 0, 6, 4, 0, 1]);
    p[22..28].copy_from_slice(&address("a").1);
    p[28..32].copy_from_slice(&address("a").0);
    p[38..42].copy_from_slice(&address("b").0);
    fabric.route("a", &p);
    assert!(b.try_recv().is_err());
    fabric
        .apply(
            "ab",
            "a",
            "b",
            &ConnectionDirection::OneWay,
            &[PermissionKind::Ports],
            &[22],
        )
        .unwrap();
    fabric.route("a", &p);
    assert!(b.try_recv().is_ok());
    p[28] ^= 1;
    fabric.route("a", &p);
    assert!(b.try_recv().is_err());
}
#[tokio::test]
async fn fabric_socket_framing_and_disconnect_cleanup() {
    let fabric = Fabric::default();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut source = TcpStream::connect(listener.local_addr().unwrap())
        .await
        .unwrap();
    fabric
        .attach("a", listener.accept().await.unwrap().0)
        .unwrap();
    let mut b = peer(&fabric, "b");
    fabric
        .apply(
            "ab",
            "a",
            "b",
            &ConnectionDirection::OneWay,
            &[PermissionKind::Ports],
            &[22],
        )
        .unwrap();
    let p = tcp("a", "b", 44444, 22, 2);
    source.write_u32(p.len() as u32).await.unwrap();
    source.write_all(&p).await.unwrap();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), b.recv())
            .await
            .unwrap()
            .unwrap(),
        p
    );
    source.write_u32(1000000).await.unwrap();
    tokio::time::timeout(Duration::from_secs(2), async {
        while fabric.connected("a") {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}
