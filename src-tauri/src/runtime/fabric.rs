//! Private, host-only Ethernet fabric. Each socket is a separate identity; guest
//! supplied MAC/IP addresses cannot impersonate another environment. No routing
//! to the host/LAN, IPv6, broadcast forwarding, or fragmented IP is permitted.
pub(crate) mod file_service;
#[cfg(test)]
mod full_vm_test;
#[cfg(test)]
mod integration;
#[cfg(test)]
mod tests;
use super::RuntimeManager;
use crate::models::{ConnectionDirection, Environment, EnvironmentKind, PermissionKind, SelectedConnectionFolder};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::mpsc,
};

pub fn address(id: &str) -> ([u8; 4], [u8; 6]) {
    let hash = Sha256::digest(id.as_bytes());
    let ip = [10, 192 + hash[0] % 32, hash[1], 2 + hash[2] % 252];
    (ip, [0x52, 0x54, 0x4f, ip[1], ip[2], ip[3]])
}
pub fn ip_text(id: &str) -> String {
    let (ip, _) = address(id);
    ip.map(|v| v.to_string()).join(".")
}
pub fn mac_text(id: &str) -> String {
    let (_, mac) = address(id);
    mac.map(|v| format!("{v:02x}")).join(":")
}
pub fn qemu_args(id: &str, port: u16, micro: bool) -> [String; 4] {
    [
        "-netdev".into(),
        format!("socket,id=odprivate,listen=127.0.0.1:{port}"),
        "-device".into(),
        format!(
            "{},netdev=odprivate,mac={}",
            if micro { "virtio-net-device" } else { "e1000e" },
            mac_text(id)
        ),
    ]
}

#[derive(Default, Clone)]
pub struct Fabric(Arc<Mutex<State>>);
#[derive(Default)]
struct State {
    peers: HashMap<String, Peer>,
    rules: HashMap<String, Rule>,
}
struct Peer {
    gateway_access: Option<Arc<std::sync::atomic::AtomicBool>>,
    // Reserve the authorized gateway port until the peer ends. Keeping only
    // the accepted stream would let another listener reuse the allowed port.
    gateway_listener: Option<tokio::net::TcpListener>,
    file_context: Option<super::connection_files::SharedFiles>,
    files: Option<mpsc::Sender<Vec<u8>>>,
    identity: ([u8; 4], [u8; 6]),
    generation: String,
    tx: mpsc::Sender<Vec<u8>>,
}
struct Rule {
    last_sweep: Instant,
    source: String,
    target: String,
    both: bool,
    network: bool,
    ports: Vec<u16>,
    flows: HashMap<Flow, Instant>,
}
#[derive(Hash, Eq, PartialEq, Clone)]
struct Flow {
    source: String,
    target: String,
    protocol: u8,
    source_port: u16,
    target_port: u16,
}
impl Flow {
    fn reverse(&self) -> Self {
        Self {
            source: self.target.clone(),
            target: self.source.clone(),
            protocol: self.protocol,
            source_port: self.target_port,
            target_port: self.source_port,
        }
    }
}

impl Fabric {
    pub fn allows_tcp(&self, source: &str, address: &str, port: u16) -> bool {
        let state = self.0.lock().unwrap();
        let Some((target, _)) = state.peers.iter().find(|(id, p)| ip_text(id) == address && !p.tx.is_closed()) else { return false; };
        state.rules.values().any(|r| ((r.source == source && &r.target == target) || (r.both && r.target == source && &r.source == target)) && (r.network || r.ports.contains(&port)))
    }
    pub fn enable_files(&self, id: &str, files: super::connection_files::SharedFiles) {
        if let Some(peer) = self.0.lock().unwrap().peers.get_mut(id) {
            if peer.files.is_none() {
                peer.file_context = Some(files.clone());
                peer.files = Some(file_service::start(id.into(), files, peer.tx.clone()));
            }
        }
    }
    pub fn connected(&self, id: &str) -> bool {
        self.0
            .lock()
            .unwrap()
            .peers
            .get(id)
            .is_some_and(|p| !p.tx.is_closed())
    }
    pub fn remove(&self, id: &str) {
        self.0.lock().unwrap().rules.remove(id);
    }
    pub fn detach(&self, id: &str) {
        let mut state = self.0.lock().unwrap();
        if let Some(peer) = state.peers.remove(id) {
            if let Some(files) = peer.file_context {
                files.remove_environment(id);
            }
        }
        for rule in state.rules.values_mut() {
            rule.flows.retain(|flow, _| flow.source != id && flow.target != id);
        }
    }
    pub fn apply(
        &self,
        id: &str,
        source: &str,
        target: &str,
        direction: &ConnectionDirection,
        permissions: &[PermissionKind],
        ports: &[u16],
    ) -> Result<String, String> {
        let mut state = self.0.lock().unwrap();
        if ![source, target]
            .iter()
            .all(|id| state.peers.get(*id).is_some_and(|p| !p.tx.is_closed()))
        {
            return Err("Private network adapter is not connected. Stop and start both environments to load the updated runtime, then retry the connection.".into());
        }
        // Reconciliation must not break live TCP sessions when nothing changed.
        let both = *direction == ConnectionDirection::Bidirectional;
        let network = permissions.contains(&PermissionKind::Network);
        if !state.rules.get(id).is_some_and(|r| {
            r.source == source
                && r.target == target
                && r.both == both
                && r.network == network
                && r.ports == ports
        }) {
            state.rules.insert(
                id.into(),
                Rule {
                    last_sweep: Instant::now(),
                    source: source.into(),
                    target: target.into(),
                    both,
                    network,
                    ports: ports.to_vec(),
                    flows: HashMap::new(),
                },
            );
        }
        Ok(format!("private:{id}"))
    }

    pub fn attach(&self, id: &str, stream: TcpStream) -> Result<(), String> {
        let mut state = self.0.lock().unwrap();
        if state
            .peers
            .keys()
            .any(|other| other != id && address(other).0 == address(id).0)
        {
            return Err("Private network address collision. Create a new environment with a different identifier; no existing connection was changed.".into());
        }
        let (tx, mut rx) = mpsc::channel::<Vec<u8>>(128);
        let generation = uuid::Uuid::new_v4().to_string();
        state.peers.insert(
            id.into(),
            Peer {
                gateway_access: None,
                gateway_listener: None,
                file_context: None,
                files: None,
                identity: address(id),
                generation: generation.clone(),
                tx,
            },
        );
        let fabric = self.clone();
        let id = id.to_owned();
        tokio::spawn(async move {
            let (mut reader, mut writer) = stream.into_split();
            let input = async {
                loop {
                    let size = reader.read_u32().await? as usize;
                    if !(14..=65536).contains(&size) {
                        return Err(std::io::Error::other("invalid Ethernet frame size"));
                    }
                    let mut packet = vec![0; size];
                    reader.read_exact(&mut packet).await?;
                    if !fabric
                        .0
                        .lock()
                        .unwrap()
                        .peers
                        .get(&id)
                        .is_some_and(|p| p.generation == generation)
                    {
                        return Ok(());
                    }
                    fabric.route(&id, &packet);
                }
                #[allow(unreachable_code)]
                Ok::<(), std::io::Error>(())
            };
            let output = async {
                while let Some(packet) = rx.recv().await {
                    writer.write_u32(packet.len() as u32).await?;
                    writer.write_all(&packet).await?;
                }
                Ok::<(), std::io::Error>(())
            };
            tokio::select! { _ = input => {}, _ = output => {} }
            let mut state = fabric.0.lock().unwrap();
            if state
                .peers
                .get(&id)
                .is_some_and(|p| p.generation == generation)
            {
                if let Some(files) = state.peers.get(&id).and_then(|p| p.file_context.as_ref()) {
                    files.remove_environment(&id);
                }
                state.peers.remove(&id);
            }
            for rule in state.rules.values_mut() {
                rule.flows.retain(|f, _| f.source != id && f.target != id);
            }
        });
        Ok(())
    }

    fn route(&self, source: &str, packet: &[u8]) {
        let mut state = self.0.lock().unwrap();
        let Some(peer) = state.peers.get(source) else {
            return;
        };
        let (source_ip, source_mac) = peer.identity;
        if packet.len() < 14 || packet[6..12] != source_mac {
            return;
        }
        if let Some(reply) = dhcp(packet, source_ip, source_mac) {
            if let Some(peer) = state.peers.get(source) {
                let _ = peer.tx.try_send(reply);
            }
            return;
        }
        let ether_type = u16::from_be_bytes([packet[12], packet[13]]);
        let (target_ip, flow, new_flow) = match ether_type {
            0x0806 => {
                if packet.len() < 42
                    || packet[14..20] != [0, 1, 8, 0, 6, 4]
                    || ![1, 2].contains(&packet[21])
                    || packet[20] != 0
                    || packet[22..28] != source_mac
                    || packet[28..32] != source_ip
                {
                    return;
                }
                (<[u8; 4]>::try_from(&packet[38..42]).unwrap(), None, false)
            }
            0x0800 => {
                let Some(ip) = ipv4(packet) else {
                    return;
                };
                if ip[12..16] != source_ip {
                    return;
                }
                let offset = (ip[0] & 15) as usize * 4;
                let payload = &ip[offset..];
                let (sport, dport, initial) = match ip[9] {
                    6 if payload.len() >= 20
                        && payload[12] >> 4 >= 5
                        && (payload[12] >> 4) as usize * 4 <= payload.len() =>
                    {
                        (be16(payload, 0), be16(payload, 2), payload[13] & 0x17 == 2)
                    }
                    17 if payload.len() >= 8 => (be16(payload, 0), be16(payload, 2), true),
                    1 if payload.len() >= 8 && [0, 8].contains(&payload[0]) => {
                        (be16(payload, 4), be16(payload, 4), payload[0] == 8)
                    }
                    _ => return,
                };
                (
                    <[u8; 4]>::try_from(&ip[16..20]).unwrap(),
                    Some((ip[9], sport, dport)),
                    initial,
                )
            }
            _ => return,
        };
        if target_ip == file_service::IP {
            if ether_type == 0x0806 || packet[..6] == file_service::MAC {
                if let Some(tx) = state.peers.get(source).and_then(|p| p.files.as_ref()) {
                    let _ = tx.try_send(packet.to_vec());
                }
            }
            return;
        }
        let Some(target) = state
            .peers
            .iter()
            .find(|(_, peer)| peer.identity.0 == target_ip)
            .map(|(id, _)| id.clone())
        else {
            return;
        };
        if source == target
            || (ether_type == 0x0800 && packet[..6] != state.peers[&target].identity.1)
        {
            return;
        }
        let now = Instant::now();
        let permitted = state.rules.values_mut().any(|rule| {
            let forward = rule.source == source && rule.target == target;
            let reverse = rule.target == source && rule.source == target;
            if !forward && !reverse {
                return false;
            }
            let Some((protocol, source_port, target_port)) = flow else {
                return true;
            }; // ARP only between explicitly connected peers.
            if protocol == 6 && new_flow && !(forward || rule.both && reverse) {
                return false;
            }
            // Sweep occasionally, not once per packet in a large file transfer.
            if now.duration_since(rule.last_sweep) >= Duration::from_secs(30) {
                rule.flows
                    .retain(|_, last| now.duration_since(*last) < Duration::from_secs(300));
                rule.last_sweep = now;
            }
            let key = Flow {
                source: source.into(),
                target: target.clone(),
                protocol,
                source_port,
                target_port,
            };
            if let Some(last) = rule
                .flows
                .get_mut(&key)
                .filter(|last| now.duration_since(**last) < Duration::from_secs(300))
            {
                *last = now;
                return true;
            }
            if let Some(last) = rule
                .flows
                .get_mut(&key.reverse())
                .filter(|last| now.duration_since(**last) < Duration::from_secs(300))
            {
                *last = now;
                return true;
            }
            if !new_flow
                || !(forward || rule.both && reverse)
                || !(rule.network || protocol == 6 && rule.ports.contains(&target_port))
                || rule.flows.len() >= 4096
            {
                return false;
            }
            rule.flows.insert(key, now);
            true
        });
        if permitted {
            if let Some(peer) = state.peers.get(&target) {
                let _ = peer.tx.try_send(packet.to_vec());
            }
        }
    }
}
fn be16(p: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes([p[offset], p[offset + 1]])
}
fn ipv4(packet: &[u8]) -> Option<&[u8]> {
    let p = packet.get(14..)?;
    if p.len() < 20 || p[0] >> 4 != 4 || p[0] & 15 < 5 || be16(p, 6) & 0x3fff != 0 {
        return None;
    }
    let size = be16(p, 2) as usize;
    if size < (p[0] & 15) as usize * 4 || size > p.len() {
        return None;
    }
    Some(&p[..size])
}
fn checksum(p: &[u8]) -> u16 {
    let mut sum: u32 = p
        .chunks(2)
        .map(|s| u16::from_be_bytes([s[0], *s.get(1).unwrap_or(&0)]) as u32)
        .sum();
    while sum >> 16 != 0 {
        sum = (sum & 65535) + (sum >> 16);
    }
    !(sum as u16)
}

// DHCP supplies an address and subnet only: it must never replace the guest's
// Internet gateway or DNS. A custom image may use the same address statically.
fn dhcp(packet: &[u8], ip: [u8; 4], mac: [u8; 6]) -> Option<Vec<u8>> {
    if be16(packet, 12) != 0x0800 {
        return None;
    }
    let p = ipv4(packet)?;
    let offset = (p[0] & 15) as usize * 4;
    if p[9] != 17 {
        return None;
    }
    let udp = p.get(offset..)?;
    if udp.len() < 248 || be16(udp, 0) != 68 || be16(udp, 2) != 67 {
        return None;
    }
    let request = &udp[8..];
    if request[0..3] != [1, 1, 6]
        || request[28..34] != mac
        || request[236..240] != [99, 130, 83, 99]
    {
        return None;
    }
    let mut message = 0;
    let mut pos = 240;
    while pos < request.len() {
        let tag = request[pos];
        pos += 1;
        if tag == 255 {
            break;
        }
        if tag == 0 {
            continue;
        }
        let len = *request.get(pos)? as usize;
        pos += 1;
        let value = request.get(pos..pos + len)?;
        pos += len;
        if tag == 53 && len == 1 {
            message = value[0];
        }
        if tag == 54 && value != [10, 192, 0, 1] {
            return None;
        }
        if tag == 50 && value != ip {
            return None;
        }
    }
    if ![1, 3].contains(&message) {
        return None;
    }
    let mut bootp = vec![0; 240];
    bootp[0..3].copy_from_slice(&[2, 1, 6]);
    bootp[4..8].copy_from_slice(&request[4..8]);
    bootp[10..12].copy_from_slice(&request[10..12]);
    bootp[16..20].copy_from_slice(&ip);
    bootp[20..24].copy_from_slice(&[10, 192, 0, 1]);
    bootp[28..34].copy_from_slice(&mac);
    bootp[236..240].copy_from_slice(&[99, 130, 83, 99]);
    bootp.extend_from_slice(&[
        53,
        1,
        if message == 1 { 2 } else { 5 },
        54,
        4,
        10,
        192,
        0,
        1,
        1,
        4,
        255,
        224,
        0,
        0,
        51,
        4,
        0,
        1,
        81,
        128,
        255,
    ]);
    let size = 20 + 8 + bootp.len();
    let mut reply = vec![0; 14 + 28];
    reply[..6].fill(255);
    reply[6..12].copy_from_slice(&[0x52, 0x54, 0x4f, 192, 0, 1]);
    reply[12..14].copy_from_slice(&[8, 0]);
    reply[14] = 0x45;
    reply[16..18].copy_from_slice(&(size as u16).to_be_bytes());
    reply[22] = 64;
    reply[23] = 17;
    reply[26..30].copy_from_slice(&[10, 192, 0, 1]);
    reply[30..34].fill(255);
    let check = checksum(&reply[14..34]);
    reply[24..26].copy_from_slice(&check.to_be_bytes());
    reply[34..36].copy_from_slice(&67u16.to_be_bytes());
    reply[36..38].copy_from_slice(&68u16.to_be_bytes());
    reply[38..40].copy_from_slice(&((8 + bootp.len()) as u16).to_be_bytes());
    reply.extend(bootp);
    Some(reply)
}

impl RuntimeManager {
    pub(crate) async fn prepare_shared_fabric_peer(&self, environment: &Environment) -> Result<String, String> {
        let id = environment.runtime_id.as_deref().unwrap_or(&environment.id).to_owned();
        if environment.kind == EnvironmentKind::Container && !self.fabric.connected(&id) {
            self.attach_fabric_container(environment).await?;
        }
        if !self.fabric.connected(&id) {
            return Err("Start the environment to connect its private network adapter".into());
        }
        Ok(id)
    }
    pub(crate) async fn open_bridge_peer(
        &self,
        connection_id: &str,
        local: &Environment,
        remote_id: &str,
        source_id: &str,
        target_id: &str,
        direction: &ConnectionDirection,
        permissions: &[PermissionKind],
        ports: &[u16],
    ) -> Result<TcpStream, String> {
        let local_id = self.prepare_shared_fabric_peer(local).await?;
        if remote_id == local_id || self.fabric.connected(remote_id) {
            return Err("This shared network peer is already connected on this computer".into());
        }
        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await.map_err(|_| "Cannot prepare private sharing bridge")?;
        let relay = TcpStream::connect(listener.local_addr().map_err(|_| "Cannot prepare private sharing bridge")?)
            .await.map_err(|_| "Cannot prepare private sharing bridge")?;
        let (fabric_socket, _) = listener.accept().await.map_err(|_| "Cannot prepare private sharing bridge")?;
        self.fabric.attach(remote_id, fabric_socket)?;
        if let Err(error) = self.fabric.apply(connection_id, source_id, target_id, direction, permissions, ports) {
            self.fabric.detach(remote_id);
            return Err(error);
        }
        Ok(relay)
    }
    pub(crate) fn close_bridge_peer(&self, connection_id: &str, remote_id: &str) {
        self.fabric.remove(connection_id);
        self.fabric.detach(remote_id);
    }
    pub(crate) fn fabric_clone(&self) -> Fabric { self.fabric.clone() }
    #[cfg(test)]
    pub async fn apply_environment_connection(
        &self,
        id: &str,
        source: &Environment,
        target: &Environment,
        direction: &ConnectionDirection,
        permissions: &[PermissionKind],
        ports: &[u16],
    ) -> Result<String, String> {
        self.apply_environment_connection_with_folders(id, source, target, direction, permissions, ports, &[], false).await
    }
    pub async fn apply_environment_connection_with_folders(
        &self,
        id: &str,
        source: &Environment,
        target: &Environment,
        direction: &ConnectionDirection,
        permissions: &[PermissionKind],
        ports: &[u16],
        selected: &[SelectedConnectionFolder],
        commands: bool,
    ) -> Result<String, String> {
        if source.runtime.starts_with("shared://") || target.runtime.starts_with("shared://") {
            if permissions.is_empty() { return Ok(format!("remote:commands:{id}")); }
            return self.apply_remote_connection(id, source, target, direction, permissions, ports).await;
        }
        let source_id = source.runtime_id.as_deref().unwrap_or(&source.id);
        let target_id = target.runtime_id.as_deref().unwrap_or(&target.id);
        if selected.is_empty() && !commands && source.kind == EnvironmentKind::Container && target.kind == EnvironmentKind::Container
            && self.workload_options(source_id)?.hosts.is_empty() && self.workload_options(target_id)?.hosts.is_empty()
            && self.same_storage(source_id, target_id)?
            && self.container_provider(source_id)? == self.container_provider(target_id)? {
            return self
                .apply_container_connection(id, source_id, target_id, direction, permissions, ports)
                .await;
        }
        if permissions.contains(&PermissionKind::Secrets) {
            return Err("Secret-directory sharing requires two containers on the same engine. Use Files/Data for cross-engine or VM connection folders.".into());
        }
        for environment in [source, target] {
            if environment.kind == EnvironmentKind::Container {
                self.attach_fabric_container(environment).await?;
            }
        }
        let rule = self
            .fabric
            .apply(id, source_id, target_id, direction, permissions, ports)?;
        if let Err(error) = self
            .apply_shared_files(id, source, target, direction, permissions, selected, commands)
            .await
        {
            self.fabric.remove(id);
            self.remove_shared_files(id).await;
            return Err(error);
        }
        if self.shared_files.available(source_id) {
            self.fabric
                .enable_files(source_id, self.shared_files.clone());
        }
        if self.shared_files.available(target_id) {
            self.fabric
                .enable_files(target_id, self.shared_files.clone());
        }
        Ok(rule)
    }
    pub async fn remove_environment_connection(
        &self,
        id: &str,
        source_id: &str,
        target_id: &str,
        containers: bool,
    ) -> Result<(), String> {
        if self.remove_remote_connection(id).await { return Ok(()); }
        let managed_service = self.shared_files.has(id);
        self.fabric.remove(id);
        self.remove_shared_files(id).await;
        if containers && !managed_service && self.same_storage(source_id, target_id)? && self.container_provider(source_id)? == self.container_provider(target_id)? {
            self.remove_container_connection(id, source_id, target_id)
                .await?;
        }
        Ok(())
    }
    async fn attach_fabric_container(&self, environment: &Environment) -> Result<(), String> {
        let id = environment.runtime_id.as_deref().unwrap_or(&environment.id);
        if self.fabric.connected(id) {
            return Ok(());
        }
        if self.container_provider(id)? == crate::models::RuntimeProviderKind::YougoriCuda {
            let endpoint = self.container_endpoint(id).await?;
            let (stream, _) = super::host_relay::channel(&endpoint, "/v1/fabric/stream",
                serde_json::json!({"id":id,"address":ip_text(id),"mac":mac_text(id)})).await?;
            return self.fabric.attach(id,stream);
        }
        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .map_err(|e| e.to_string())?;
        let port = listener.local_addr().map_err(|e| e.to_string())?.port();
        let token = format!(
            "{}{}",
            uuid::Uuid::new_v4().simple(),
            uuid::Uuid::new_v4().simple()
        );
        let gateway_access = Arc::new(std::sync::atomic::AtomicBool::new(true));
        self.grant_qemu_host_service(id, port, Arc::downgrade(&gateway_access), true).await?;
        self.workspace_request(environment,"/v1/fabric/attach",serde_json::json!({"id":id,"port":port,"token":token,"address":ip_text(id),"mac":mac_text(id)})).await?;
        let stream = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let (mut stream, _) = listener.accept().await.map_err(|e| e.to_string())?;
                let mut secret = [0; 64];
                if tokio::time::timeout(Duration::from_secs(1), stream.read_exact(&mut secret))
                    .await
                    .is_ok_and(|r| r.is_ok())
                    && secret == token.as_bytes()
                {
                    return Ok::<_, String>(stream);
                }
            }
        })
        .await
        .map_err(|_| "Container private network did not connect")??;
        self.fabric.attach(id, stream)?;
        if let Some(peer) = self.fabric.0.lock().map_err(|_| "Private network unavailable")?.peers.get_mut(id) {
            peer.gateway_access = Some(gateway_access);
            peer.gateway_listener = Some(listener);
        }
        Ok(())
    }
}
