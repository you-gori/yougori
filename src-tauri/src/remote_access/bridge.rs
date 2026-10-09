//! An authenticated WebSocket carries only private Ethernet frames between two
//! explicitly connected guests. It never exposes the host network or engine API.
use super::*;
use futures_util::{SinkExt, StreamExt};
use std::collections::HashSet;
use tokio::{io::{AsyncReadExt, AsyncWriteExt}, net::TcpStream};
use tokio_tungstenite::{tungstenite::Message, WebSocketStream};

pub(crate) fn websocket_config() -> tokio_tungstenite::tungstenite::protocol::WebSocketConfig {
    tokio_tungstenite::tungstenite::protocol::WebSocketConfig::default()
        .read_buffer_size(16 * 1024)
        .write_buffer_size(16 * 1024)
        .max_write_buffer_size(256 * 1024)
        .max_message_size(Some(65536))
        .max_frame_size(Some(65536))
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Open {
    pub token: String,
    pub connection_id: String,
    pub peer_id: String,
    pub direction: ConnectionDirection,
    pub source_remote: bool,
    pub permissions: Vec<PermissionKind>,
    pub ports: Vec<u16>,
}

pub(crate) fn valid_id(value: &str) -> bool {
    !value.is_empty() && value.len() <= 80
        && value.bytes().all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

pub(crate) fn validate_open(open: &Open) -> Result<(), String> {
    if !open.connection_id.starts_with("conn-") || !valid_id(&open.connection_id) || !valid_id(&open.peer_id) {
        return Err("Invalid private connection identity".into());
    }
    if open.permissions.is_empty() || open.permissions.iter().any(|permission| !matches!(permission, PermissionKind::Network | PermissionKind::Ports)) {
        return Err("Shared connections grant network or TCP ports only".into());
    }
    if open.ports.len() > 64 || open.ports.contains(&0) || open.ports.iter().collect::<HashSet<_>>().len() != open.ports.len()
        || (!open.permissions.contains(&PermissionKind::Ports) && !open.ports.is_empty())
        || (open.permissions.contains(&PermissionKind::Ports) && open.ports.is_empty() && !open.permissions.contains(&PermissionKind::Network)) {
        return Err("Choose up to 64 distinct TCP ports between 1 and 65535".into());
    }
    Ok(())
}

#[derive(Default)]
struct FrameReceiver {
    prefix: [u8; 4],
    prefix_bytes: usize,
    frame: Vec<u8>,
    frame_bytes: usize,
}
impl FrameReceiver {
    // read is cancellation safe. Keep partial prefix/body state outside the
    // select future so heartbeat and WebSocket events cannot discard bytes.
    async fn receive(&mut self, socket: &mut TcpStream) -> std::io::Result<Vec<u8>> {
        loop {
            if self.prefix_bytes < self.prefix.len() {
                let read = socket.read(&mut self.prefix[self.prefix_bytes..]).await?;
                if read == 0 { return Err(std::io::ErrorKind::UnexpectedEof.into()); }
                self.prefix_bytes += read;
                if self.prefix_bytes < self.prefix.len() { continue; }
            }
            if self.frame.is_empty() {
                let size = u32::from_be_bytes(self.prefix) as usize;
                if !(14..=65536).contains(&size) {
                    return Err(std::io::Error::other("Invalid private network frame size"));
                }
                self.frame.resize(size, 0);
            }
            let read = socket.read(&mut self.frame[self.frame_bytes..]).await?;
            if read == 0 { return Err(std::io::ErrorKind::UnexpectedEof.into()); }
            self.frame_bytes += read;
            if self.frame_bytes == self.frame.len() {
                self.prefix_bytes = 0;
                self.frame_bytes = 0;
                return Ok(std::mem::take(&mut self.frame));
            }
        }
    }
}

pub(crate) async fn relay<S>(websocket: &mut WebSocketStream<S>, mut socket: TcpStream, cancel: CancellationToken, fabric: crate::runtime::fabric::Fabric, real_peer_id: &str) -> Result<(), String>
where S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin {
    let mut heartbeat = tokio::time::interval(Duration::from_secs(20));
    let mut check_peer = tokio::time::interval(Duration::from_secs(5));
    let mut last_response = tokio::time::Instant::now();
    let mut frames = FrameReceiver::default();
    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => return Err("The shared session ended".into()),
            _ = check_peer.tick() => {
                if !fabric.connected(real_peer_id) { return Err("The connected environment stopped".into()) }
                if last_response.elapsed() > Duration::from_secs(65) { return Err("The private sharing tunnel stopped responding".into()) }
            },
            _ = heartbeat.tick() => websocket.send(Message::Ping(Vec::new().into())).await.map_err(|_| "Private connection interrupted")?,
            received = websocket.next() => match received {
                Some(Ok(Message::Binary(frame))) if (14..=65536).contains(&frame.len()) => {
                    last_response = tokio::time::Instant::now();
                    socket.write_u32(frame.len() as u32).await.map_err(|_| "Private network adapter stopped")?;
                    socket.write_all(&frame).await.map_err(|_| "Private network adapter stopped")?;
                }
                Some(Ok(Message::Ping(data))) => { last_response = tokio::time::Instant::now(); websocket.send(Message::Pong(data)).await.map_err(|_| "Private connection interrupted")?; },
                Some(Ok(Message::Pong(_))) => { last_response = tokio::time::Instant::now(); },
                Some(Ok(Message::Close(_))) | None => return Ok(()),
                _ => return Err("Invalid private network frame".into()),
            },
            frame = frames.receive(&mut socket) => {
                let frame = frame.map_err(|_| "Private network adapter stopped")?;
                websocket.send(Message::Binary(frame.into())).await.map_err(|_| "Private connection interrupted")?;
            },
        }
    }
}

pub(super) async fn serve_authenticated(websocket: &mut WebSocketStream<TcpStream>, app: AppHandle) -> Result<(), String> {
    let first = tokio::time::timeout(Duration::from_secs(10), websocket.next()).await
        .map_err(|_| "Private connection sign-in timed out")?
        .ok_or("Private connection sign-in ended")?
        .map_err(|_| "Invalid private connection sign-in")?;
    let Message::Text(text) = first else { return Err("Invalid private connection sign-in".into()) };
    if text.len() > 4096 { return Err("Private connection sign-in is too large".into()); }
    let open: Open = serde_json::from_str(&text).map_err(|_| "Invalid private connection sign-in")?;
    validate_open(&open)?;
    if open.token.len() != 64 || !open.token.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("Sign in to this share again".into());
    }
    let manager = app.state::<RemoteAccess>();
    let _slot = manager.bridge_slots.clone().try_acquire_owned().map_err(|_| "The owner has too many private connections open")?;
    let (grant_id, session_owner, cancel) = {
        let mut sessions = manager.sessions.lock().await;
        let session = sessions.get_mut(&hash(&open.token))
            .filter(|session| session.expires > now() && session.seen > now() - 900)
            .ok_or("Session expired or revoked; connect again")?;
        session.seen = now();
        (session.grant.clone(), session.owner.clone(), session.cancel.clone())
    };
    let grant = manager.db.lock().await.grants.iter().find(|grant| grant.id == grant_id).cloned().ok_or("Share no longer exists")?;
    if !grant.active() || grant.permission != Permission::Control || grant.target_id == "my-pc" {
        return Err("The owner has not granted Full Control of this environment".into());
    }
    check_control_scope(&app, &grant.target_id, grant.acknowledge_existing_access).await?;
    let environment = target(&app, &grant.target_id)?;
    if environment.status != EnvironmentStatus::Running { return Err("The owner's environment is not running".into()); }
    let state = app.state::<PlatformStore>().snapshot()?;
    if state.environments.iter().any(|env| env.id == open.peer_id || env.runtime_id.as_deref() == Some(&open.peer_id)) {
        return Err("The remote peer identity conflicts with an environment on this computer".into());
    }
    let runtime = app.state::<RuntimeManager>();
    let owner_id = runtime.prepare_shared_fabric_peer(&environment).await?;
    let source_id = if open.source_remote { &owner_id } else { &open.peer_id };
    let target_id = if open.source_remote { &open.peer_id } else { &owner_id };
    let rule_id = format!("remote-{}", hash(&format!("{session_owner}:{}", open.connection_id)));
    let socket = runtime.open_bridge_peer(&rule_id, &environment, &open.peer_id, source_id, target_id, &open.direction, &open.permissions, &open.ports).await?;
    if websocket.send(Message::Text(json!({"ok":true,"fabricId":owner_id}).to_string().into())).await.is_err() {
        runtime.close_bridge_peer(&rule_id, &open.peer_id);
        return Err("Private connection interrupted".into());
    }
    manager.audit(&grant.id, "private connection opened", true).await;
    let touch = async {
        loop {
            tokio::time::sleep(Duration::from_secs(20)).await;
            let mut sessions = manager.sessions.lock().await;
            let Some(session) = sessions.get_mut(&hash(&open.token)) else { break };
            if session.expires <= now() { break }
            session.seen = now();
        }
    };
    tokio::select! {
        _ = relay(websocket, socket, cancel, runtime.fabric_clone(), &owner_id) => {},
        _ = touch => {},
    }
    runtime.close_bridge_peer(&rule_id, &open.peer_id);
    manager.audit(&grant.id, "private connection closed", true).await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn open(permissions: Vec<PermissionKind>, ports: Vec<u16>) -> Open {
        Open { token: "a".repeat(64), connection_id: "conn-00000000-0000-0000-0000-000000000000".into(), peer_id: "env-peer".into(), direction: ConnectionDirection::OneWay, source_remote: false, permissions, ports }
    }
    #[test]
    fn bridge_request_never_accepts_file_or_secret_access_or_ambiguous_ports() {
        assert!(validate_open(&open(vec![PermissionKind::Ports], vec![3000])).is_ok());
        assert!(validate_open(&open(vec![PermissionKind::Network], vec![])).is_ok());
        assert!(validate_open(&open(vec![PermissionKind::Files], vec![])).is_err());
        assert!(validate_open(&open(vec![PermissionKind::Secrets], vec![])).is_err());
        assert!(validate_open(&open(vec![PermissionKind::Ports], vec![3000, 3000])).is_err());
        assert!(validate_open(&open(vec![PermissionKind::Ports], vec![])).is_err());
    }

    async fn pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let first = TcpStream::connect(listener.local_addr().unwrap()).await.unwrap();
        let (second, _) = listener.accept().await.unwrap();
        (first, second)
    }
    fn arp(source: &str, target: &str) -> Vec<u8> {
        let (source_ip, source_mac) = crate::runtime::fabric::address(source);
        let (target_ip, _) = crate::runtime::fabric::address(target);
        let mut frame = Vec::with_capacity(42);
        frame.extend_from_slice(&[255; 6]);
        frame.extend_from_slice(&source_mac);
        frame.extend_from_slice(&[0x08, 0x06, 0, 1, 8, 0, 6, 4, 0, 1]);
        frame.extend_from_slice(&source_mac);
        frame.extend_from_slice(&source_ip);
        frame.extend_from_slice(&[0; 6]);
        frame.extend_from_slice(&target_ip);
        frame
    }
    async fn read_frame(socket: &mut TcpStream) -> Vec<u8> {
        let length = socket.read_u32().await.unwrap() as usize;
        let mut frame = vec![0; length];
        socket.read_exact(&mut frame).await.unwrap();
        frame
    }
    #[tokio::test]
    async fn websocket_bridge_carries_binary_frames_in_both_directions() {
        let fabric = crate::runtime::fabric::Fabric::default();
        let (real, _real_guest) = pair().await;
        fabric.attach("env-real", real).unwrap();
        let (bridge_socket, mut peer_socket) = pair().await;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            tokio_tungstenite::accept_async(socket).await.unwrap()
        });
        let (mut client, _) = tokio_tungstenite::connect_async(format!("ws://{address}")).await.unwrap();
        let mut server = server.await.unwrap();
        let cancel = CancellationToken::new();
        let relay_task = tokio::spawn(async move { relay(&mut server, bridge_socket, cancel, fabric, "env-real").await });
        let inbound = vec![7_u8; 14];
        client.send(Message::Binary(inbound.clone().into())).await.unwrap();
        let received = tokio::time::timeout(Duration::from_secs(3), async {
            let length = peer_socket.read_u32().await.unwrap() as usize;
            let mut frame = vec![0; length];
            peer_socket.read_exact(&mut frame).await.unwrap();
            frame
        }).await.unwrap();
        assert_eq!(received, inbound);
        let outbound = vec![9_u8; 14];
        peer_socket.write_u32(outbound.len() as u32).await.unwrap();
        peer_socket.write_all(&outbound).await.unwrap();
        let echoed = tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                if let Some(Ok(Message::Binary(frame))) = client.next().await { break frame.to_vec() }
            }
        }).await.unwrap();
        assert_eq!(echoed, outbound);
        relay_task.abort();
    }

    #[tokio::test]
    async fn websocket_bridge_keeps_partial_frames_when_other_events_arrive() {
        let fabric = crate::runtime::fabric::Fabric::default();
        let (real, _real_guest) = pair().await;
        fabric.attach("env-real", real).unwrap();
        let (bridge_socket, mut peer_socket) = pair().await;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            tokio_tungstenite::accept_async(socket).await.unwrap()
        });
        let (mut client, _) = tokio_tungstenite::connect_async(format!("ws://{address}")).await.unwrap();
        let mut server = server.await.unwrap();
        let cancel = CancellationToken::new();
        let shutdown = cancel.clone();
        let relay_task = tokio::spawn(async move { relay(&mut server, bridge_socket, cancel, fabric, "env-real").await });
        let frame = vec![0xab_u8; 42];
        let prefix = (frame.len() as u32).to_be_bytes();
        // Both a prefix and a payload can be incomplete when a WebSocket event
        // wins select. Each interruption must retain the bytes already read.
        for fragment in [&prefix[..2], &prefix[2..], &frame[..7]] {
            peer_socket.write_all(fragment).await.unwrap();
            tokio::time::sleep(Duration::from_millis(40)).await;
            client.send(Message::Ping(vec![3].into())).await.unwrap();
            tokio::time::timeout(Duration::from_secs(2), async {
                loop {
                    match client.next().await {
                        Some(Ok(Message::Pong(data))) if data.as_ref() == [3] => break,
                        Some(Ok(Message::Ping(data))) => client.send(Message::Pong(data)).await.unwrap(),
                        Some(Ok(_)) => {},
                        reply => panic!("bridge ended during partial frame: {reply:?}"),
                    }
                }
            }).await.unwrap();
        }
        peer_socket.write_all(&frame[7..]).await.unwrap();
        let received = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                match client.next().await {
                    Some(Ok(Message::Binary(data))) => break data.to_vec(),
                    Some(Ok(Message::Ping(data))) => client.send(Message::Pong(data)).await.unwrap(),
                    Some(Ok(_)) => {},
                    reply => panic!("partial frame was lost: {reply:?}"),
                }
            }
        }).await.unwrap();
        shutdown.cancel();
        let _ = relay_task.await.unwrap();
        assert_eq!(received, frame);
    }

    #[tokio::test]
    async fn two_private_fabrics_route_only_the_connected_guests_across_websocket() {
        let client_fabric = crate::runtime::fabric::Fabric::default();
        let owner_fabric = crate::runtime::fabric::Fabric::default();
        let (client_real, mut client_guest) = pair().await;
        let (owner_real, mut owner_guest) = pair().await;
        client_fabric.attach("env-client", client_real).unwrap();
        owner_fabric.attach("env-owner", owner_real).unwrap();
        let (client_virtual, client_bridge) = pair().await;
        let (owner_virtual, owner_bridge) = pair().await;
        client_fabric.attach("env-owner", client_virtual).unwrap();
        owner_fabric.attach("env-client", owner_virtual).unwrap();
        for fabric in [&client_fabric, &owner_fabric] {
            fabric.apply("conn-private", "env-client", "env-owner", &ConnectionDirection::Bidirectional, &[PermissionKind::Network], &[]).unwrap();
        }
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            tokio_tungstenite::accept_async(socket).await.unwrap()
        });
        let (mut client_websocket, _) = tokio_tungstenite::connect_async(format!("ws://{address}")).await.unwrap();
        let mut owner_websocket = server.await.unwrap();
        let client_task = tokio::spawn({ let fabric = client_fabric.clone(); async move { let _ = relay(&mut client_websocket, client_bridge, CancellationToken::new(), fabric, "env-client").await; } });
        let owner_task = tokio::spawn({ let fabric = owner_fabric.clone(); async move { let _ = relay(&mut owner_websocket, owner_bridge, CancellationToken::new(), fabric, "env-owner").await; } });
        let outbound = arp("env-client", "env-owner");
        client_guest.write_u32(outbound.len() as u32).await.unwrap();
        client_guest.write_all(&outbound).await.unwrap();
        assert_eq!(tokio::time::timeout(Duration::from_secs(3), read_frame(&mut owner_guest)).await.unwrap(), outbound);
        let reply = arp("env-owner", "env-client");
        owner_guest.write_u32(reply.len() as u32).await.unwrap();
        owner_guest.write_all(&reply).await.unwrap();
        assert_eq!(tokio::time::timeout(Duration::from_secs(3), read_frame(&mut client_guest)).await.unwrap(), reply);
        client_task.abort();
        owner_task.abort();
    }
}
