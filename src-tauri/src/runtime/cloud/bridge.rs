//! TCP-only synthetic private NIC. No host socket destination is accepted from
//! a guest. Fabric identity and saved rules gate both directions on every frame.
use super::*;
use crate::runtime::fabric::{address, file_service::Wire};
use smoltcp::{
    iface::{Config, Interface, SocketHandle, SocketSet},
    socket::tcp,
    time::Instant as Tick,
    wire::{EthernetAddress, IpAddress, IpCidr},
};
use std::{collections::VecDeque, time::Instant};
use tokio::net::{TcpListener, TcpStream};

struct Slot {
    handle: SocketHandle,
    stream: String,
    pending: VecDeque<u8>,
    open: bool,
    opening: bool,
    closing: bool,
    sent_eof: bool,
    touched: Instant,
    request: Option<String>,
    target: Option<(String, u16)>,
}
fn socket() -> tcp::Socket<'static> {
    let mut socket = tcp::Socket::new(
        tcp::SocketBuffer::new(vec![0; 65536]),
        tcp::SocketBuffer::new(vec![0; 65536]),
    );
    socket.set_timeout(Some(smoltcp::time::Duration::from_secs(60)));
    socket
}
pub async fn start(
    id: &str,
    fabric: Fabric,
    session: Session,
    mut events: mpsc::Receiver<Value>,
) -> Result<(), String> {
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .map_err(|e| e.to_string())?;
    let mut transport = TcpStream::connect(listener.local_addr().map_err(|e| e.to_string())?)
        .await
        .map_err(|e| e.to_string())?;
    let (peer, _) = listener.accept().await.map_err(|e| e.to_string())?;
    drop(listener);
    fabric.attach(id, peer)?;
    let id = id.to_owned();
    tokio::spawn(async move {
        let (ip, mac) = address(&id);
        let (outgoing, mut frames) = mpsc::channel::<Vec<u8>>(128);
        let mut wire = Wire {
            incoming: VecDeque::new(),
            outgoing,
        };
        let mut config = Config::new(EthernetAddress(mac).into());
        config.random_seed =
            u64::from_le_bytes(*uuid::Uuid::new_v4().as_bytes().first_chunk::<8>().unwrap());
        let mut iface = Interface::new(config, &mut wire, Tick::from_millis(0));
        iface.update_ip_addrs(|ips| {
            let _ = ips.push(IpCidr::new(IpAddress::v4(ip[0], ip[1], ip[2], ip[3]), 11));
        });
        let mut sockets = SocketSet::new(vec![]);
        let mut slots: Vec<Slot> = vec![];
        let mut tasks = tokio::task::JoinSet::new();
        let start = Instant::now();
        let mut input = Vec::<u8>::new();
        let mut chunk = [0u8; 65536];
        let mut next_port = 30000u16;
        loop {
            let tick = Tick::from_millis(start.elapsed().as_millis() as i64);
            iface.poll(tick, &mut wire, &mut sockets);
            for slot in &mut slots {
                let sock = sockets.get_mut::<tcp::Socket>(slot.handle);
                if let Some((target, port)) = &slot.target {
                    if !fabric.allows_tcp(&id, target, *port) {
                        sock.abort();
                    }
                }
                if sock.state() == tcp::State::Established && !slot.opening {
                    slot.opening = true;
                    if let Some(request) = slot.request.take() {
                        let _ = session
                            .tx
                            .try_send(json!({"requestId":request,"result":{"ok":true}}));
                    } else {
                        let session = session.clone();
                        let stream = slot.stream.clone();
                        let port = sock.local_endpoint().unwrap().port;
                        tasks.spawn(async move {
                            let event = if session
                                .request("stream/open", json!({"streamId":stream,"port":port}))
                                .await
                                .is_ok()
                            {
                                "ready"
                            } else {
                                "closed"
                            };
                            let _ = session
                                .bridge
                                .send(json!({"event":event,"streamId":stream}))
                                .await;
                        });
                    }
                }
                if sock.can_recv() && slot.open {
                    // Reserve before consuming TCP bytes: another RPC producer
                    // may fill the channel between a capacity check and send.
                    if let Ok(permit) = session.tx.try_reserve() {
                        let mut data = vec![0; 32768];
                        if let Ok(n) = sock.recv_slice(&mut data) {
                            data.truncate(n);
                            permit.send(json!({"event":"data","streamId":slot.stream,"data":B64.encode(data)}));
                            slot.touched = Instant::now();
                        }
                    }
                }
                if sock.can_send() && !slot.pending.is_empty() {
                    let data = slot.pending.make_contiguous();
                    if let Ok(n) = sock.send_slice(data) {
                        slot.pending.drain(..n);
                        slot.touched = Instant::now();
                    }
                }
                if sock.state() == tcp::State::CloseWait
                    && !sock.can_recv()
                    && slot.open
                    && !slot.sent_eof
                {
                    if let Ok(permit) = session.tx.try_reserve() {
                        permit.send(json!({"event":"eof","streamId":slot.stream}));
                        slot.sent_eof = true;
                    }
                }
                // A remote FIN follows its data, not the queue that may still
                // contain it. Retain the read half for request/response clients.
                if slot.closing && slot.pending.is_empty() {
                    sock.close();
                }
                if slot.touched.elapsed() > Duration::from_secs(90) {
                    sock.abort();
                }
            }
            let mut index = 0;
            while index < slots.len() {
                // FIN can move to TimeWait while application bytes remain in
                // the receive buffer. Drain them before sending "closed".
                let socket = sockets.get::<tcp::Socket>(slots[index].handle);
                if !socket.is_open() && (!socket.can_recv() || !slots[index].open) {
                    let slot = slots.swap_remove(index);
                    sockets.remove(slot.handle);
                    if let Some(request) = slot.request {
                        let _=session.tx.try_send(json!({"requestId":request,"error":"Connected node did not accept the port"}));
                    }
                    let _ = session
                        .tx
                        .try_send(json!({"event":"closed","streamId":slot.stream}));
                } else {
                    index += 1;
                }
            }
            iface.poll(tick, &mut wire, &mut sockets);
            while tasks.try_join_next().is_some() {}
            tokio::select! {
                result=transport.read(&mut chunk)=>{
                    let Ok(n)=result else{break}; if n==0 {break;} input.extend_from_slice(&chunk[..n]);
                    while input.len()>=4 {
                        let size=u32::from_be_bytes(input[..4].try_into().unwrap()) as usize;
                        if !(14..=65536).contains(&size) {return;}
                        if input.len()<4+size {break;}
                        let packet=input[4..4+size].to_vec();input.drain(..4+size);
                        // A SYN already checked by Fabric opens a loopback-only
                        // cloud service, never an arbitrary remote LAN address.
                        if packet.len()>=54 && packet[12..14]==[8,0] && packet[23]==6 {
                            let offset=14+(packet[14]&15) as usize*4;
                            if packet.len()>=offset+20 && packet[offset+13]&0x17==2 && slots.len()<64 {
                                let port=u16::from_be_bytes(packet[offset+2..offset+4].try_into().unwrap());
                                if !slots.iter().any(|s| {let sock=sockets.get::<tcp::Socket>(s.handle);sock.state()==tcp::State::Listen && sock.local_endpoint().is_some_and(|ep|ep.port==port)}) {
                                    let mut sock=socket();if sock.listen(port).is_ok(){slots.push(Slot{handle:sockets.add(sock),stream:uuid::Uuid::new_v4().to_string(),pending:VecDeque::new(),open:false,opening:false,closing:false,sent_eof:false,touched:Instant::now(),request:None,target:None});}
                                }
                            }
                        }
                        wire.incoming.push_back(packet);
                    }
                },
                packet=frames.recv()=>{let Some(packet)=packet else{break}; if transport.write_u32(packet.len() as u32).await.is_err() || transport.write_all(&packet).await.is_err(){break;}},
                event=events.recv()=>{
                    let Some(event)=event else{break};
                    match event["event"].as_str().unwrap_or("") {
                        "shutdown"=>break,
                        "connect"=>{
                            let target=event["address"].as_str().unwrap_or("");let port=event["port"].as_u64().filter(|p|*p>0&&*p<=65535).unwrap_or(0) as u16;
                            let address=target.parse::<std::net::Ipv4Addr>();
                            if slots.len()>=64 || !fabric.allows_tcp(&id,target,port) || address.is_err() {
                                let _=session.tx.try_send(json!({"requestId":event["requestId"],"error":"Access denied. Connect this node and allow this TCP port in Yougori."}));continue;
                            }
                            let octets=address.unwrap().octets();let mut sock=socket();next_port=if next_port>=60000{30000}else{next_port+1};
                            if sock.connect(iface.context(),(IpAddress::v4(octets[0],octets[1],octets[2],octets[3]),port),next_port).is_ok(){slots.push(Slot{handle:sockets.add(sock),stream:event["streamId"].as_str().unwrap_or("").into(),pending:VecDeque::new(),open:false,opening:false,closing:false,sent_eof:false,touched:Instant::now(),request:Some(event["requestId"].as_str().unwrap_or("").into()),target:Some((target.into(),port))});}
                        },
                        "ready"=>{if let Some(slot)=slots.iter_mut().find(|s|Some(s.stream.as_str())==event["streamId"].as_str()){slot.open=true;}},
                        "data"=>{if let Some(slot)=slots.iter_mut().find(|s|Some(s.stream.as_str())==event["streamId"].as_str()) {match B64.decode(event["data"].as_str().unwrap_or("")){Ok(data) if data.len()<=32768 && slot.pending.len()+data.len()<=262144=>{slot.pending.extend(data);slot.touched=Instant::now();},_=>sockets.get_mut::<tcp::Socket>(slot.handle).abort()}}},
                        "eof" | "closed"=>{if let Some(slot)=slots.iter_mut().find(|s|Some(s.stream.as_str())==event["streamId"].as_str()){slot.closing=true;}},
                        _=>break,
                    }
                },
                _=tokio::time::sleep(Duration::from_millis(if slots.is_empty(){500}else{10}))=>{},
            }
        }
        tasks.abort_all();
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{ConnectionDirection, PermissionKind};
    fn endpoint() -> (Session, mpsc::Receiver<Value>, mpsc::Receiver<Value>) {
        let (tx, rx) = mpsc::channel(128);
        let (bridge, events) = mpsc::channel(128);
        (
            Session {
                tx,
                pending: Default::default(),
                stop: Default::default(),
                bridge,
                info: Value::Null,
                share_helper_ready: Arc::new(tokio::sync::Mutex::new(false)),
                termination: Default::default(),
                followers: Default::default(),
            },
            rx,
            events,
        )
    }
    async fn receive(rx: &mut mpsc::Receiver<Value>) -> Value {
        tokio::time::timeout(Duration::from_secs(8), rx.recv())
            .await
            .expect("bridge response timed out")
            .unwrap()
    }
    #[tokio::test]
    async fn private_tcp_bridge_preserves_bytes_enforces_direction_and_revokes_live_access() {
        let fabric = Fabric::default();
        let (source, mut source_rx, source_events) = endpoint();
        let (target, mut target_rx, target_events) = endpoint();
        start(
            "env-cloud-source",
            fabric.clone(),
            source.clone(),
            source_events,
        )
        .await
        .unwrap();
        start(
            "env-local-target",
            fabric.clone(),
            target.clone(),
            target_events,
        )
        .await
        .unwrap();
        fabric
            .apply(
                "conn-bridge",
                "env-cloud-source",
                "env-local-target",
                &ConnectionDirection::OneWay,
                &[PermissionKind::Ports],
                &[5432],
            )
            .unwrap();
        // The second endpoint uses the same TCP stack to emulate a local guest;
        // its adapter speaks real Ethernet to the production Fabric.
        source.bridge.send(json!({"event":"connect","address":super::super::super::fabric::ip_text("env-local-target"),"port":5432,"streamId":"from-cloud","requestId":"connect-1"})).await.unwrap();
        let open = receive(&mut target_rx).await;
        assert_eq!(open["path"], "stream/open");
        assert_eq!(open["body"]["port"], 5432);
        let stream = open["body"]["streamId"].clone();
        target
            .pending
            .lock()
            .unwrap()
            .remove(open["requestId"].as_str().unwrap())
            .unwrap()
            .send(Ok(json!({"ok":true})))
            .unwrap();
        let ready = receive(&mut source_rx).await;
        assert_eq!(ready["requestId"], "connect-1");
        assert!(ready.get("error").is_none());
        source
            .bridge
            .send(json!({"event":"ready","streamId":"from-cloud"}))
            .await
            .unwrap();
        let bytes: Vec<u8> = (0..32768).map(|i| (i % 256) as u8).collect();
        source
            .bridge
            .send(json!({"event":"data","streamId":"from-cloud","data":B64.encode(&bytes)}))
            .await
            .unwrap();
        let mut received = vec![];
        while received.len() < bytes.len() {
            let frame = receive(&mut target_rx).await;
            assert_eq!(frame["event"], "data");
            received.extend(B64.decode(frame["data"].as_str().unwrap()).unwrap());
        }
        assert_eq!(received, bytes);
        target.bridge.send(json!({"event":"data","streamId":stream,"data":B64.encode(b"database reply\0\xff")})).await.unwrap();
        let reply = receive(&mut source_rx).await;
        assert_eq!(reply["event"], "data");
        assert_eq!(
            B64.decode(reply["data"].as_str().unwrap()).unwrap(),
            b"database reply\0\xff"
        );
        target.bridge.send(json!({"event":"connect","address":super::super::super::fabric::ip_text("env-cloud-source"),"port":5432,"streamId":"denied","requestId":"backwards"})).await.unwrap();
        assert!(receive(&mut target_rx).await["error"]
            .as_str()
            .unwrap()
            .contains("Access denied"));
        source.bridge.send(json!({"event":"connect","address":"192.168.1.1","port":80,"streamId":"denied-lan","requestId":"lan"})).await.unwrap();
        assert!(receive(&mut source_rx).await["error"].is_string());
        fabric.remove("conn-bridge");
        let revoked = receive(&mut source_rx).await;
        assert_eq!(revoked["event"], "closed");
        source
            .bridge
            .send(json!({"event":"shutdown"}))
            .await
            .unwrap();
        target
            .bridge
            .send(json!({"event":"shutdown"}))
            .await
            .unwrap();
    }
    #[tokio::test]
    async fn tcp_half_close_drains_large_queued_response_without_truncating() {
        let fabric = Fabric::default();
        let (source, mut source_rx, source_events) = endpoint();
        let (target, mut target_rx, target_events) = endpoint();
        start(
            "env-half-source",
            fabric.clone(),
            source.clone(),
            source_events,
        )
        .await
        .unwrap();
        start(
            "env-half-target",
            fabric.clone(),
            target.clone(),
            target_events,
        )
        .await
        .unwrap();
        fabric
            .apply(
                "conn-half",
                "env-half-source",
                "env-half-target",
                &ConnectionDirection::Bidirectional,
                &[PermissionKind::Ports],
                &[8080],
            )
            .unwrap();
        source.bridge.send(json!({"event":"connect","address":super::super::super::fabric::ip_text("env-half-target"),"port":8080,"streamId":"request","requestId":"open"})).await.unwrap();
        let open = receive(&mut target_rx).await;
        let stream = open["body"]["streamId"].clone();
        target
            .pending
            .lock()
            .unwrap()
            .remove(open["requestId"].as_str().unwrap())
            .unwrap()
            .send(Ok(json!({"ok":true})))
            .unwrap();
        assert_eq!(receive(&mut source_rx).await["requestId"], "open");
        source
            .bridge
            .send(json!({"event":"ready","streamId":"request"}))
            .await
            .unwrap();
        source
            .bridge
            .send(json!({"event":"data","streamId":"request","data":B64.encode(b"request")}))
            .await
            .unwrap();
        source
            .bridge
            .send(json!({"event":"eof","streamId":"request"}))
            .await
            .unwrap();
        let request = receive(&mut target_rx).await;
        assert_eq!(
            B64.decode(request["data"].as_str().unwrap()).unwrap(),
            b"request"
        );
        assert_eq!(receive(&mut target_rx).await["event"], "eof");
        let payload: Vec<u8> = (0..262144).map(|i| (i % 251) as u8).collect();
        for part in payload.chunks(32768) {
            target
                .bridge
                .send(json!({"event":"data","streamId":stream,"data":B64.encode(part)}))
                .await
                .unwrap();
        }
        target
            .bridge
            .send(json!({"event":"eof","streamId":stream}))
            .await
            .unwrap();
        let mut received = vec![];
        loop {
            let event = receive(&mut source_rx).await;
            if event["event"] == "closed" || event["event"] == "eof" {
                break;
            }
            assert_eq!(event["event"], "data");
            received.extend(B64.decode(event["data"].as_str().unwrap()).unwrap());
        }
        assert_eq!(received.len(), payload.len(), "Half-close truncated the response");
        assert!(received == payload, "Half-close changed response bytes");
        source
            .bridge
            .send(json!({"event":"shutdown"}))
            .await
            .unwrap();
        target
            .bridge
            .send(json!({"event":"shutdown"}))
            .await
            .unwrap();
    }
}
