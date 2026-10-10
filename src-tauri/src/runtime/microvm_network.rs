//! Host-side filtering for the VM's shared control/internet NIC.
//! The guest cannot undo this policy by changing its routes or firewall.
use std::collections::{HashMap, HashSet};
use std::sync::{
    atomic::{AtomicBool, AtomicU8, Ordering},
    Arc, Weak,
};
use std::time::{Duration, Instant};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::RwLock,
    task::JoinHandle,
};
#[path = "host_addresses.rs"]
mod host_address_inventory;

const ADDRESS_LEASE: Duration = Duration::from_secs(1);
const MAX_INTERNET_FLOWS: usize = 4096;
const MAX_ADDRESS_LOOKUPS_PER_SECOND: u32 = 256;

pub(super) struct MicroVmNetwork {
    enabled: Arc<RwLock<bool>>,
    host: Arc<std::sync::Mutex<HostPolicy>>,
    failed: Arc<AtomicBool>,
    connected: Arc<AtomicU8>,
    _address_monitor: host_address_inventory::Monitor,
    tasks: Vec<JoinHandle<Result<(), String>>>,
    arguments: Vec<String>,
}
impl Drop for MicroVmNetwork {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}
impl MicroVmNetwork {
    pub async fn new(enabled: bool, qmp_port: u16) -> Result<Self, String> {
        // Register before taking the initial snapshot; a simultaneous address
        // change invalidates the snapshot instead of leaving an unobserved IP.
        let address_monitor = host_address_inventory::Monitor::start()?;
        let mut host_policy = HostPolicy {
            address_changes: address_monitor.state(),
            ..HostPolicy::default()
        };
        host_policy
            .refresh_addresses_with(Instant::now(), host_address_inventory::ipv4_addresses)?;
        let mut result = Self {
            enabled: Arc::new(RwLock::new(enabled)),
            host: Arc::new(std::sync::Mutex::new(host_policy)),
            failed: Arc::new(AtomicBool::new(false)),
            connected: Arc::new(AtomicU8::new(0)),
            _address_monitor: address_monitor,
            tasks: Vec::new(),
            arguments: Vec::new(),
        };
        for direction in ["rx", "tx"] {
            let outgoing = TcpListener::bind("127.0.0.1:0")
                .await
                .map_err(|e| e.to_string())?;
            let incoming = TcpListener::bind("127.0.0.1:0")
                .await
                .map_err(|e| e.to_string())?;
            let out_port = outgoing.local_addr().map_err(|e| e.to_string())?.port();
            let in_port = incoming.local_addr().map_err(|e| e.to_string())?.port();
            result.arguments.extend([
                "-chardev".into(), format!("socket,id=internet-{direction}-out,host=127.0.0.1,port={out_port}"),
                "-chardev".into(), format!("socket,id=internet-{direction}-in,host=127.0.0.1,port={in_port}"),
                "-object".into(), format!("filter-redirector,id=internet-{direction},netdev=net0,queue={direction},outdev=internet-{direction}-out,indev=internet-{direction}-in"),
            ]);
            let policy = result.enabled.clone();
            let host = result.host.clone();
            let failed = result.failed.clone();
            let connected = result.connected.clone();
            // QEMU rx is guest -> backend; tx is backend -> guest.
            result.tasks.push(tokio::spawn(async move {
                let ((mut reader, _), (mut writer, _)) =
                    tokio::time::timeout(Duration::from_secs(30), async {
                        tokio::try_join!(outgoing.accept(), incoming.accept())
                    })
                    .await
                    .map_err(|_| "MicroVM network filter connection timed out".to_string())?
                    .map_err(|e| e.to_string())?;
                connected.fetch_add(1, Ordering::Release);
                let forwarding: Result<(), String> = async {
                    reader.set_nodelay(true).map_err(|e| e.to_string())?;
                    writer.set_nodelay(true).map_err(|e| e.to_string())?;
                    let mut packet = Vec::new();
                    loop {
                        let length = reader.read_u32().await.map_err(|e| e.to_string())? as usize;
                        if !(14..=65536).contains(&length) {
                            return Err("Invalid MicroVM network frame".into());
                        }
                        packet.resize(length, 0);
                        reader
                            .read_exact(&mut packet)
                            .await
                            .map_err(|e| e.to_string())?;
                        let enabled = policy.read().await;
                        let allowed = {
                            let mut host = host.lock().map_err(|_| "VM host policy unavailable")?;
                            host.preflight_with(
                                &packet,
                                direction == "rx",
                                *enabled,
                                Instant::now(),
                                host_address_inventory::ipv4_addresses,
                            ) && host.allows(&packet, direction == "rx", *enabled)
                        };
                        if allowed {
                            tokio::time::timeout(Duration::from_secs(5), async {
                                writer.write_u32(length as u32).await?;
                                writer.write_all(&packet).await
                            })
                            .await
                            .map_err(|_| "MicroVM network filter stalled".to_string())?
                            .map_err(|e| e.to_string())?;
                        }
                    }
                }
                .await;
                if forwarding.is_err() {
                    failed.store(true, Ordering::Release);
                    // QEMU's redirector bypasses an absent output socket. Keep
                    // both sockets alive on failure and additionally lower the
                    // link before waiting for normal VM teardown.
                    let _ = super::vm::qmp_execute_bounded(
                        qmp_port,
                        "set_link",
                        Some(serde_json::json!({"name":"net0", "up":false})),
                        Duration::from_secs(5),
                    )
                    .await;
                    std::future::pending::<()>().await;
                }
                forwarding
            }));
        }
        Ok(result)
    }
    pub fn arguments(&self) -> &[String] {
        &self.arguments
    }
    pub fn grant_host_service(&self, port: u16, lifetime: Weak<AtomicBool>) -> Result<(), String> {
        let mut policy = self.host.lock().map_err(|_| "VM host policy unavailable")?;
        policy.services.retain(|_, grants| {
            grants.retain(active);
            !grants.is_empty()
        });
        if port == 0 || !active(&lifetime) || policy.services.len() >= 4096 {
            return Err("Invalid or exhausted VM host service grant".into());
        }
        let grants = policy.services.entry(port).or_default();
        if !grants.iter().any(|grant| grant.ptr_eq(&lifetime)) {
            grants.push(lifetime);
        }
        Ok(())
    }
    pub fn set_local_services(&self, ports: &[u16]) -> Result<(), String> {
        if ports.len() > 4096 || ports.contains(&0) {
            return Err("Invalid VM local service ports".into());
        }
        self.host
            .lock()
            .map_err(|_| "VM host policy unavailable")?
            .local_services = ports.iter().copied().collect();
        Ok(())
    }
    pub async fn set_enabled(&self, enabled: bool) -> Result<(), String> {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        while self.connected.load(Ordering::Acquire) < 2 {
            if self.tasks.iter().any(|task| task.is_finished())
                || tokio::time::Instant::now() >= deadline
            {
                return Err("VM network filter did not connect. Restart this environment.".into());
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        if self.failed.load(Ordering::Acquire) || self.tasks.iter().any(|task| task.is_finished()) {
            return Err("MicroVM network filter stopped. Restart this environment.".into());
        }
        // Wait for in-flight writes before acknowledging a disconnected cable.
        let mut state = self.enabled.write().await;
        let mut host = self.host.lock().map_err(|_| "VM host policy unavailable")?;
        if enabled {
            host.refresh_addresses_with(Instant::now(), host_address_inventory::ipv4_addresses)?;
        }
        host.verified_flows.clear();
        *state = enabled;
        Ok(())
    }
}

fn active(grant: &Weak<AtomicBool>) -> bool {
    grant
        .upgrade()
        .is_some_and(|value| value.load(Ordering::Acquire))
}
#[derive(Default)]
struct HostPolicy {
    host_addresses: HashSet<[u8; 4]>,
    address_changes: Arc<host_address_inventory::Changes>,
    address_generation: u64,
    address_checked_at: Option<Instant>,
    verified_flows: HashMap<InternetFlow, Instant>,
    lookup_window: Option<Instant>,
    address_lookups: u32,
    services: HashMap<u16, Vec<Weak<AtomicBool>>>,
    local_services: HashSet<u16>,
    // Only SYNs received from QEMU's trusted host-forwarding direction create
    // reply grants. A guest choosing source port 7443 cannot create a grant.
    replies: HashMap<([u8; 4], [u8; 4], u16, u16), Instant>,
}
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
struct InternetFlow {
    guest: [u8; 4],
    peer: [u8; 4],
    protocol: u8,
    guest_port: u16,
    peer_port: u16,
}

fn internet_flow(packet: &[u8], outbound: bool) -> Option<(InternetFlow, bool)> {
    if packet.len() < 34 || packet[12..14] != [8, 0] || packet[14] != 0x45 {
        return None;
    }
    let total = usize::from(u16::from_be_bytes([packet[16], packet[17]]));
    if total < 20
        || packet.len() < 14 + total
        || u16::from_be_bytes([packet[20], packet[21]]) & 0x3fff != 0
    {
        return None;
    }
    let (guest, peer) = if outbound {
        (&packet[26..30], &packet[30..34])
    } else {
        (&packet[30..34], &packet[26..30])
    };
    if outbound && !(guest[..3] == [10, 0, 2] && (4..=254).contains(&guest[3])) {
        return None;
    }
    let transport = &packet[34..14 + total];
    let protocol = packet[23];
    let (source, target, syn) = match protocol {
        6 if transport.len() >= 20 => {
            let header = usize::from(transport[12] >> 4) * 4;
            if header < 20 || header > transport.len() {
                return None;
            }
            (
                u16::from_be_bytes([transport[0], transport[1]]),
                u16::from_be_bytes([transport[2], transport[3]]),
                transport[13] & 0x12 == 2,
            )
        }
        17 if transport.len() >= 8 => (
            u16::from_be_bytes([transport[0], transport[1]]),
            u16::from_be_bytes([transport[2], transport[3]]),
            false,
        ),
        6 | 17 => return None,
        _ => (0, 0, false),
    };
    let (guest_port, peer_port) = if outbound {
        (source, target)
    } else {
        (target, source)
    };
    Some((
        InternetFlow {
            guest: guest.try_into().ok()?,
            peer: peer.try_into().ok()?,
            protocol,
            guest_port,
            peer_port,
        },
        syn,
    ))
}

impl HostPolicy {
    fn snapshot_healthy(&self, now: Instant) -> bool {
        self.address_changes.healthy()
            && self.address_generation == self.address_changes.generation()
            && self
                .address_checked_at
                .is_some_and(|checked| now.saturating_duration_since(checked) < ADDRESS_LEASE)
    }

    fn refresh_addresses_with(
        &mut self,
        now: Instant,
        mut lookup: impl FnMut() -> Result<HashSet<[u8; 4]>, String>,
    ) -> Result<(), String> {
        let result = (|| {
            if !self.address_changes.healthy() {
                return Err("Host IPv4 change watcher stopped. Restart this environment.".into());
            }
            let generation = self.address_changes.generation();
            let addresses = lookup()?;
            if addresses.is_empty() {
                return Err("Host IPv4 inventory is empty; network access remains blocked".into());
            }
            if !self.address_changes.healthy() || generation != self.address_changes.generation() {
                return Err("Host IPv4 changed during enumeration. Retry network access.".into());
            }
            if generation != self.address_generation || addresses != self.host_addresses {
                self.verified_flows.clear();
            }
            self.host_addresses = addresses;
            self.address_generation = generation;
            self.address_checked_at = Some(now);
            Ok(())
        })();
        if result.is_err() {
            self.address_checked_at = None;
            self.verified_flows.clear();
        }
        result
    }

    fn preflight_with(
        &mut self,
        packet: &[u8],
        outbound: bool,
        internet: bool,
        now: Instant,
        lookup: impl FnMut() -> Result<HashSet<[u8; 4]>, String>,
    ) -> bool {
        let Some((flow, syn)) = internet_flow(packet, outbound) else {
            return true;
        };
        // The fixed gateway's scoped capabilities do not depend on host addresses.
        // Reject-only classes need no OS query; their packet rules run below.
        if flow.peer == [10, 0, 2, 2]
            || flow.peer[0] == 0
            || flow.peer[0] == 127
            || flow.peer[..2] == [169, 254]
            || flow.peer[0] >= 224
        {
            return true;
        }
        let healthy = self.snapshot_healthy(now);
        let internal = flow.peer[..3] == [10, 0, 2];
        if !internet && !self.host_addresses.contains(&flow.peer) {
            return true;
        }
        if healthy
            && (internal
                || !outbound
                || (!syn
                    && self.verified_flows.get(&flow).is_some_and(|checked| {
                        now.saturating_duration_since(*checked) < ADDRESS_LEASE
                    })))
        {
            return true;
        }
        if !self.address_changes.healthy() {
            return false;
        }
        if self
            .lookup_window
            .is_none_or(|started| now.saturating_duration_since(started) >= Duration::from_secs(1))
        {
            self.lookup_window = Some(now);
            self.address_lookups = 0;
        }
        if self.address_lookups >= MAX_ADDRESS_LOOKUPS_PER_SECOND {
            return false;
        }
        self.address_lookups += 1;
        if self.refresh_addresses_with(now, lookup).is_err() {
            return false;
        }
        // Cache only destinations that remain Internet peers or have a live
        // explicit physical-host capability after this fresh inventory.
        let authorized_host = self.host_addresses.contains(&flow.peer)
            && (self.local_services.contains(&flow.peer_port)
                || self
                    .services
                    .get(&flow.peer_port)
                    .is_some_and(|grants| grants.iter().any(active))
                || self
                    .replies
                    .get(&(flow.guest, flow.peer, flow.guest_port, flow.peer_port))
                    .is_some_and(|touched| {
                        now.saturating_duration_since(*touched) < Duration::from_secs(300)
                    }));
        if outbound
            && !internal
            && ((internet && !self.host_addresses.contains(&flow.peer)) || authorized_host)
        {
            if self.verified_flows.len() >= MAX_INTERNET_FLOWS {
                self.verified_flows
                    .retain(|_, checked| now.saturating_duration_since(*checked) < ADDRESS_LEASE);
                if self.verified_flows.len() >= MAX_INTERNET_FLOWS {
                    return false;
                }
            }
            self.verified_flows.insert(flow, now);
        }
        true
    }

    fn allows(&mut self, packet: &[u8], outbound: bool, internet: bool) -> bool {
        if packet.len() < 14 {
            return false;
        }
        match u16::from_be_bytes([packet[12], packet[13]]) {
            // ARP has no routable payload; needed for the control gateway.
            0x0806 => packet.len() >= 42 && packet[14..20] == [0, 1, 8, 0, 6, 4],
            0x0800 => {
                if packet.len() < 34 || packet[14] >> 4 != 4 {
                    return false;
                }
                let header = usize::from(packet[14] & 15) * 4;
                let total = usize::from(u16::from_be_bytes([packet[16], packet[17]]));
                if header != 20 || total < header || packet.len() < 14 + total {
                    return false;
                }
                if u16::from_be_bytes([packet[20], packet[21]]) & 0x3fff != 0 {
                    return false;
                }
                let peer = if outbound {
                    &packet[30..34]
                } else {
                    &packet[26..30]
                };
                if outbound {
                    let source = &packet[26..30];
                    if source == [0, 0, 0, 0] {
                        // Only DHCP bootstrap may precede a guest address.
                        // Other source-zero traffic cannot skip fresh-flow
                        // inventory checks or acquire a host capability.
                        return packet[23] == 17
                            && total >= header + 8
                            && packet[30..34] == [255, 255, 255, 255]
                            && packet[34..38] == [0, 68, 0, 67];
                    }
                    if !(source[..3] == [10, 0, 2] && (4..=254).contains(&source[3])) {
                        return false;
                    }
                }
                let peer_address: [u8; 4] = peer.try_into().unwrap();
                if peer != [10, 0, 2, 2]
                    && self.host_addresses.contains(&peer_address)
                    && !self.snapshot_healthy(Instant::now())
                {
                    return false;
                }
                if peer == [10, 0, 2, 2] || self.host_addresses.contains(&peer_address) {
                    let transport = &packet[14 + header..14 + total];
                    // Preserve gateway diagnostics without granting host sockets.
                    if peer == [10, 0, 2, 2] && internet && packet[23] == 1 && transport.len() >= 8
                    {
                        return transport[1] == 0 && transport[0] == if outbound { 8 } else { 0 };
                    }
                    if peer == [10, 0, 2, 2] && packet[23] == 17 && transport.len() >= 8 {
                        let source = u16::from_be_bytes([transport[0], transport[1]]);
                        let target = u16::from_be_bytes([transport[2], transport[3]]);
                        return (outbound && source == 68 && target == 67)
                            || (!outbound && source == 67 && target == 68);
                    }
                    if packet[23] != 6 || transport.len() < 20 {
                        return false;
                    }
                    let tcp_header = usize::from(transport[12] >> 4) * 4;
                    if tcp_header < 20 || transport.len() < tcp_header {
                        return false;
                    }
                    let source = u16::from_be_bytes([transport[0], transport[1]]);
                    let target = u16::from_be_bytes([transport[2], transport[3]]);
                    let (guest, guest_port, host_port) = if outbound {
                        (packet[26..30].try_into().unwrap(), source, target)
                    } else {
                        (packet[30..34].try_into().unwrap(), target, source)
                    };
                    if self.local_services.contains(&host_port)
                        || self
                            .services
                            .get(&host_port)
                            .is_some_and(|grants| grants.iter().any(active))
                    {
                        return true;
                    }
                    let now = Instant::now();
                    self.replies.retain(|_, touched| {
                        now.duration_since(*touched) < Duration::from_secs(300)
                    });
                    let key = (guest, peer_address, guest_port, host_port);
                    let flags = transport[13];
                    if !outbound && flags & 0x12 == 0x02 && self.replies.len() < 4096 {
                        self.replies.insert(key, now);
                        return true;
                    }
                    // A new guest-initiated SYN is never a reply, even when its
                    // chosen tuple matches an existing host-forwarded session.
                    if outbound && flags & 0x12 == 0x02 {
                        return false;
                    }
                    if let Some(touched) = self.replies.get_mut(&key) {
                        *touched = now;
                        if flags & 0x04 != 0 {
                            self.replies.remove(&key);
                        }
                        return true;
                    }
                    return false;
                }
                // SLIRP's virtual DNS is the only other service on its internal
                // subnet. Do not let aliases or loopback/link-local targets become
                // another route to the host control plane or cloud metadata.
                let internet = internet && self.snapshot_healthy(Instant::now());
                if peer[..3] == [10, 0, 2] {
                    let transport = &packet[14 + header..14 + total];
                    let port_offset = if outbound { 2 } else { 0 };
                    return internet
                        && peer[3] == 3
                        && matches!(packet[23], 6 | 17)
                        && transport.len() >= 4
                        && u16::from_be_bytes([
                            transport[port_offset],
                            transport[port_offset + 1],
                        ]) == 53;
                }
                if internet
                    && peer[0] != 0
                    && peer[0] != 127
                    && peer[..2] != [169, 254]
                    && peer[0] < 224
                {
                    return true;
                }
                // Permit DHCP bootstrap/renewal only. DNS and IPv6 cannot bypass
                // disconnection through the shared user-network backend.
                let fragments = u16::from_be_bytes([packet[20], packet[21]]);
                if packet[23] != 17 || fragments & 0x3fff != 0 || total < header + 8 {
                    return false;
                }
                let udp = 14 + header;
                let source = u16::from_be_bytes([packet[udp], packet[udp + 1]]);
                let target = u16::from_be_bytes([packet[udp + 2], packet[udp + 3]]);
                outbound && packet[30..34] == [255, 255, 255, 255] && source == 68 && target == 67
            }
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn test_policy() -> HostPolicy {
        HostPolicy {
            host_addresses: HashSet::from([[127, 0, 0, 1]]),
            address_changes: host_address_inventory::Changes::ready_for_test(),
            address_checked_at: Some(Instant::now()),
            ..HostPolicy::default()
        }
    }
    fn ipv4(source: [u8; 4], target: [u8; 4]) -> Vec<u8> {
        let mut packet = vec![0; 42];
        packet[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
        packet[14] = 0x45;
        packet[16..18].copy_from_slice(&28u16.to_be_bytes());
        packet[23] = 17;
        packet[26..30].copy_from_slice(&source);
        packet[30..34].copy_from_slice(&target);
        packet
    }
    #[test]
    fn offline_preserves_control_but_blocks_external_traffic_both_ways() {
        let mut policy = test_policy();
        policy.host_addresses.insert([192, 168, 1, 10]);
        let guest = [10, 0, 2, 15];
        let host = [10, 0, 2, 2];
        let external = [1, 1, 1, 1];
        assert!(!policy.allows(&ipv4(guest, host), true, false));
        assert!(!policy.allows(&ipv4(host, guest), false, false));
        assert!(!policy.allows(&ipv4(guest, external), true, false));
        assert!(!policy.allows(&ipv4(external, guest), false, false));
        assert!(!policy.allows(&ipv4(guest, [10, 0, 2, 3]), true, false));
        assert!(!policy.allows(&[0; 13], true, false));
        let mut ipv6 = vec![0; 80];
        ipv6[12..14].copy_from_slice(&0x86ddu16.to_be_bytes());
        assert!(!policy.allows(&ipv6, true, false));
        assert!(!policy.allows(&ipv6, true, true));
        let mut dhcp = ipv4([0; 4], [255; 4]);
        dhcp[34..38].copy_from_slice(&[0, 68, 0, 67]);
        assert!(policy.allows(&dhcp, true, false));
        dhcp[20] = 0x20;
        assert!(!policy.allows(&dhcp, true, false));
        let mut options = ipv4(guest, host);
        options[14] = 0x46;
        assert!(!policy.allows(&options, true, false));
        let mut truncated = ipv4(guest, host);
        truncated[17] = 255;
        assert!(!policy.allows(&truncated, true, false));
        let mut arp = vec![0; 42];
        arp[12..20].copy_from_slice(&[8, 6, 0, 1, 8, 0, 6, 4]);
        assert!(policy.allows(&arp, true, false));
        assert!(policy.allows(&arp, false, false));
    }
    fn tcp(source: [u8; 4], target: [u8; 4], from: u16, to: u16, flags: u8) -> Vec<u8> {
        let mut packet = ipv4(source, target);
        packet.resize(54, 0);
        packet[16..18].copy_from_slice(&40u16.to_be_bytes());
        packet[23] = 6;
        packet[34..36].copy_from_slice(&from.to_be_bytes());
        packet[36..38].copy_from_slice(&to.to_be_bytes());
        packet[46] = 0x50;
        packet[47] = flags;
        packet
    }
    #[test]
    fn host_control_ports_are_blocked_online_and_offline_but_forwarded_replies_work() {
        let guest = [10, 0, 2, 15];
        let host = [10, 0, 2, 2];
        let mut policy = test_policy();
        policy.host_addresses.insert([192, 168, 1, 10]);
        for internet in [false, true] {
            for port in [22, 7443, 5900, 32123] {
                assert!(!policy.allows(&tcp(guest, host, 7443, port, 2), true, internet));
                assert!(!policy.allows(&tcp(guest, host, 7443, port, 0x10), true, internet));
            }
            assert!(!policy.allows(
                &tcp(guest, [192, 168, 1, 10], 40000, 8080, 2),
                true,
                internet
            ));
        }
        assert!(policy.allows(&tcp(host, guest, 40000, 7443, 2), false, false));
        assert!(policy.allows(&tcp(guest, host, 7443, 40000, 0x12), true, false));
        assert!(!policy.allows(&tcp(guest, host, 7443, 40000, 2), true, false));
        assert!(!policy.allows(&tcp([10, 0, 2, 99], host, 7443, 40000, 0x10), true, false));
        assert!(policy.allows(&tcp(guest, [1, 1, 1, 1], 40000, 443, 2), true, true));
        assert!(!policy.allows(&tcp(guest, [1, 1, 1, 1], 40000, 443, 2), true, false));
        let mut fragment = tcp(guest, host, 40000, 443, 2);
        fragment[20] = 0x20;
        assert!(!policy.allows(&fragment, true, true));
    }
    #[test]
    fn new_lan_flow_refreshes_inventory_and_address_changes_revoke_cached_flows() {
        let mut policy = test_policy();
        let now = Instant::now();
        let peer = [192, 168, 1, 20];
        let packet = tcp([10, 0, 2, 15], peer, 40000, 8080, 0x10);
        assert!(
            policy.preflight_with(&packet, true, true, now, || Ok(HashSet::from([[
                127, 0, 0, 1
            ]])))
        );
        assert!(policy.allows(&packet, true, true));
        policy.address_changes.invalidate_for_test();
        assert!(
            policy.preflight_with(&packet, true, true, now + Duration::from_millis(1), || Ok(
                HashSet::from([[127, 0, 0, 1], peer])
            ))
        );
        assert!(!policy.allows(&packet, true, true));
        assert!(policy.verified_flows.is_empty());
    }
    #[test]
    fn failed_or_empty_inventory_blocks_internet_and_preserves_scoped_gateway_services() {
        for empty in [false, true] {
            let mut policy = test_policy();
            let packet = tcp([10, 0, 2, 15], [1, 1, 1, 1], 40000, 443, 2);
            assert!(
                !policy.preflight_with(&packet, true, true, Instant::now(), || {
                    if empty {
                        Ok(HashSet::new())
                    } else {
                        Err("injected enumeration error".into())
                    }
                })
            );
            assert!(!policy.allows(&packet, true, true));
            policy.local_services.insert(12345);
            let control = tcp([10, 0, 2, 15], [10, 0, 2, 2], 40000, 12345, 2);
            assert!(
                policy.preflight_with(&control, true, true, Instant::now(), || panic!(
                    "control must not query"
                ))
            );
            assert!(policy.allows(&control, true, true));
            assert!(!policy.allows(
                &tcp([10, 0, 2, 15], [10, 0, 2, 2], 40000, 12346, 2),
                true,
                true
            ));
        }
    }
    #[test]
    fn inventory_change_during_enumeration_fails_closed() {
        let mut policy = test_policy();
        let changes = policy.address_changes.clone();
        let packet = tcp([10, 0, 2, 15], [1, 1, 1, 1], 40000, 443, 2);
        assert!(
            !policy.preflight_with(&packet, true, true, Instant::now(), || {
                changes.invalidate_for_test();
                Ok(HashSet::from([[127, 0, 0, 1]]))
            })
        );
        assert!(!policy.allows(&packet, true, true));
    }
    #[test]
    fn offline_physical_host_grant_is_revoked_when_address_becomes_remote() {
        let mut policy = test_policy();
        let local = [192, 168, 1, 10];
        let active = Arc::new(AtomicBool::new(true));
        policy.services.insert(12345, vec![Arc::downgrade(&active)]);
        policy.host_addresses.insert(local);
        let packet = tcp([10, 0, 2, 15], local, 40000, 12345, 0x10);
        assert!(
            policy.preflight_with(&packet, true, false, Instant::now(), || Ok(HashSet::from(
                [[127, 0, 0, 1], local]
            )))
        );
        assert!(policy.allows(&packet, true, false));
        policy.address_changes.invalidate_for_test();
        assert!(!policy.allows(&packet, true, false));
        assert!(
            policy.preflight_with(&packet, true, false, Instant::now(), || Ok(HashSet::from(
                [[127, 0, 0, 1]]
            )))
        );
        assert!(!policy.allows(&packet, true, false));
    }
    #[test]
    fn active_flow_lease_expires_and_new_syn_always_rechecks() {
        let mut policy = test_policy();
        let now = Instant::now();
        let packet = tcp([10, 0, 2, 15], [1, 1, 1, 1], 40000, 443, 0x10);
        let mut lookups = 0;
        assert!(policy.preflight_with(&packet, true, true, now, || {
            lookups += 1;
            Ok(HashSet::from([[127, 0, 0, 1]]))
        }));
        assert!(policy.preflight_with(
            &packet,
            true,
            true,
            now + Duration::from_millis(100),
            || panic!("warm data flow must use its bounded lease")
        ));
        assert!(
            policy.preflight_with(&packet, true, true, now + Duration::from_secs(2), || {
                lookups += 1;
                Ok(HashSet::from([[127, 0, 0, 1]]))
            })
        );
        let syn = tcp([10, 0, 2, 15], [1, 1, 1, 1], 40000, 443, 2);
        assert!(
            policy.preflight_with(&syn, true, true, now + Duration::from_secs(2), || {
                lookups += 1;
                Ok(HashSet::from([[127, 0, 0, 1]]))
            })
        );
        assert_eq!(lookups, 3);
    }
    #[test]
    fn lookup_budget_bounds_socket_churn_without_querying_every_packet() {
        let mut policy = test_policy();
        let now = Instant::now();
        let mut lookups = 0;
        for index in 0..MAX_ADDRESS_LOOKUPS_PER_SECOND {
            let packet = tcp(
                [10, 0, 2, 15],
                [1, 1, 1, 1],
                40000 + index as u16,
                443,
                0x10,
            );
            assert!(policy.preflight_with(&packet, true, true, now, || {
                lookups += 1;
                Ok(HashSet::from([[127, 0, 0, 1]]))
            }));
        }
        assert!(!policy.preflight_with(
            &tcp([10, 0, 2, 15], [1, 1, 1, 1], 60000, 443, 0x10),
            true,
            true,
            now,
            || panic!("exhausted lookup budget")
        ));
        assert!(policy.preflight_with(
            &tcp([10, 0, 2, 15], [1, 1, 1, 1], 40000, 443, 0x10),
            true,
            true,
            now,
            || panic!("existing leased flow")
        ));
        assert_eq!(lookups, MAX_ADDRESS_LOOKUPS_PER_SECOND);
    }
    #[test]
    fn flow_cache_cannot_grow_past_its_limit() {
        let mut policy = test_policy();
        let now = Instant::now();
        for port in 1..=MAX_INTERNET_FLOWS {
            policy.verified_flows.insert(
                InternetFlow {
                    guest: [10, 0, 2, 15],
                    peer: [1, 1, 1, 1],
                    protocol: 6,
                    guest_port: port as u16,
                    peer_port: 443,
                },
                now,
            );
        }
        assert!(!policy.preflight_with(
            &tcp([10, 0, 2, 15], [1, 1, 1, 1], 60000, 443, 0x10),
            true,
            true,
            now,
            || Ok(HashSet::from([[127, 0, 0, 1]]))
        ));
        assert_eq!(policy.verified_flows.len(), MAX_INTERNET_FLOWS);
    }
    #[test]
    fn dhcp_exception_applies_only_to_virtual_gateway_and_bootstrap_broadcast() {
        let mut policy = test_policy();
        let guest = [10, 0, 2, 15];
        let local = [192, 168, 1, 10];
        policy.host_addresses.insert(local);
        for internet in [false, true] {
            let mut request = ipv4(guest, local);
            request[34..38].copy_from_slice(&[0, 68, 0, 67]);
            assert!(!policy.allows(&request, true, internet));
            request[30..34].copy_from_slice(&[10, 0, 2, 2]);
            assert!(policy.allows(&request, true, internet));
            request[26..30].copy_from_slice(&[0; 4]);
            request[30..34].copy_from_slice(&[255; 4]);
            assert!(policy.allows(&request, true, internet));
        }
    }
    #[test]
    fn unassigned_guest_source_is_limited_to_dhcp_bootstrap() {
        let mut policy = test_policy();
        policy.local_services.insert(12345);
        for internet in [false, true] {
            assert!(!policy.allows(&tcp([0; 4], [1, 1, 1, 1], 40000, 443, 2), true, internet));
            assert!(!policy.allows(&tcp([0; 4], [10, 0, 2, 2], 40000, 12345, 2), true, internet));
            let mut datagram = ipv4([0; 4], [1, 1, 1, 1]);
            datagram[34..38].copy_from_slice(&[0, 68, 0, 67]);
            assert!(!policy.allows(&datagram, true, internet));
            datagram[30..34].copy_from_slice(&[255; 4]);
            assert!(policy.allows(&datagram, true, internet));
            datagram[36..38].copy_from_slice(&53u16.to_be_bytes());
            assert!(!policy.allows(&datagram, true, internet));
        }
    }
    #[tokio::test]
    async fn explicit_host_grants_end_with_the_service_and_do_not_authorize_other_ports() {
        let network = MicroVmNetwork::new(true, 0).await.unwrap();
        let active = Arc::new(AtomicBool::new(true));
        network
            .grant_host_service(12345, Arc::downgrade(&active))
            .unwrap();
        let guest = [10, 0, 2, 15];
        let host = [10, 0, 2, 2];
        {
            let mut policy = network.host.lock().unwrap();
            assert!(policy.allows(&tcp(guest, host, 40000, 12345, 2), true, true));
            assert!(!policy.allows(&tcp(guest, host, 40000, 12346, 2), true, true));
        }
        active.store(false, Ordering::Release);
        assert!(!network.host.lock().unwrap().allows(
            &tcp(guest, host, 40000, 12345, 0x10),
            true,
            true
        ));
        assert!(network
            .grant_host_service(12345, Arc::downgrade(&active))
            .is_err());
    }
    #[tokio::test]
    async fn filter_failure_retains_redirect_sockets_and_rejects_policy_updates() {
        let network = MicroVmNetwork::new(false, 0).await.unwrap();
        let mut sockets = Vec::new();
        for argument in network
            .arguments()
            .iter()
            .filter(|value| value.starts_with("socket,"))
        {
            let port: u16 = argument.rsplit("port=").next().unwrap().parse().unwrap();
            sockets.push(
                tokio::net::TcpStream::connect(("127.0.0.1", port))
                    .await
                    .unwrap(),
            );
        }
        sockets[0].write_u32(1).await.unwrap();
        tokio::time::timeout(Duration::from_secs(2), async {
            while !network.failed.load(Ordering::Acquire) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(network.set_enabled(true).await.is_err());
        // Closing the reader would make QEMU bypass its redirector.
        let mut byte = [0];
        assert!(
            tokio::time::timeout(Duration::from_millis(100), sockets[0].read(&mut byte))
                .await
                .is_err()
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "boots a disposable bundled MicroVM to verify host-enforced internet and control traffic"]
    async fn microvm_internet_toggle_preserves_control_and_host_access() -> Result<(), String> {
        use crate::models::{Priority, ResourcePolicy, ResourceRange};
        use crate::runtime::RuntimeManager;
        use std::path::Path;
        let data = tempfile::tempdir().unwrap();
        let runtime = RuntimeManager::new(Path::new(env!("CARGO_MANIFEST_DIR")), data.path())?;
        let listener = TcpListener::bind("0.0.0.0:0")
            .await
            .map_err(|e| e.to_string())?;
        let port = listener.local_addr().map_err(|e| e.to_string())?.port();
        let http = tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut request = [0; 4096];
                    let _ = stream.read(&mut request).await;
                    let _ = stream
                        .write_all(b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nOK")
                        .await;
                });
            }
        });
        let result = async {
            let vm = runtime
                .provision_micro_vm("internet-test", "builtin:alpine")
                .await?;
            // Model an existing built-in disk whose old installation was
            // removed. It must boot this installation's trusted upgrade files.
            let mut saved: serde_json::Value = serde_json::from_slice(
                &std::fs::read(&vm.source_path).map_err(|error| error.to_string())?
            ).map_err(|error| error.to_string())?;
            saved["kernel"] = serde_json::json!(data.path().join("removed-install/kernel"));
            saved["initrd"] = serde_json::json!(data.path().join("removed-install/initrd"));
            std::fs::write(&vm.source_path, serde_json::to_vec(&saved).map_err(|error| error.to_string())?)
                .map_err(|error| error.to_string())?;
            let policy = ResourcePolicy {
                cpu: ResourceRange {
                    min: 1.,
                    preferred: 1.,
                    max: 1.,
                    current: 0.,
                },
                memory_gb: ResourceRange {
                    min: 0.5,
                    preferred: 0.5,
                    max: 0.5,
                    current: 0.,
                },
                priority: Priority::Normal,
                dynamic: true,
            };
            runtime
                .start_micro_vm_with_network(
                    "internet-test",
                    &vm.disk_path,
                    &vm.source_path,
                    &policy,
                    false,
                )
                .await?;
            let host_service = Arc::new(AtomicBool::new(true));
            runtime.grant_qemu_host_service("internet-test", port, Arc::downgrade(&host_service), false).await?;
            let qmp_port = runtime.vms.lock().await.get("internet-test")
                .ok_or("MicroVM disappeared during host isolation test")?.qmp_port;
            // Prove this is an active management listener before testing its
            // guest isolation; a stale/unbound port would give a false pass.
            crate::runtime::vm::qmp_request(qmp_port, "query-status", None).await?;
            for enabled in [false, true, false, true] {
                runtime.update_vm_internet("internet-test", enabled).await?;
                let blocked_qmp = runtime.execute_micro_vm_command("internet-test", &format!(
                    "command -v nc >/dev/null && command -v timeout >/dev/null || exit 42; if timeout 3 nc -w 2 10.0.2.2:{qmp_port} </dev/null; then echo HOST_SOCKET_OPEN; exit 41; fi; echo HOST_SOCKET_BLOCKED"
                )).await?;
                if blocked_qmp.exit_code != 0 || !blocked_qmp.stdout.contains("HOST_SOCKET_BLOCKED") {
                    return Err(format!("guest reached host QMP with internet={enabled}: {blocked_qmp:?}"));
                }
                let management = runtime
                    .execute_micro_vm_command(
                        "internet-test",
                        &format!("wget -T 4 -qO- http://10.0.2.2:{port}"),
                    )
                    .await?;
                if management.exit_code != 0 || management.stdout != "OK" {
                    return Err(format!(
                        "control/PC access failed with internet={enabled}: {management:?}"
                    ));
                }
                let external = runtime
                    .execute_micro_vm_command(
                        "internet-test",
                        "wget -T 5 -qO- http://example.com",
                    )
                    .await?;
                if (external.exit_code == 0) != enabled {
                    return Err(format!("internet={enabled} not enforced: {external:?}"));
                }
            }
            // Keep the HTTP listener alive while revoking its grant. Failure
            // must be enforced by the filter, rather than a closed host socket.
            host_service.store(false, Ordering::Release);
            let revoked = runtime.execute_micro_vm_command("internet-test", &format!(
                "wget -T 2 -qO- http://10.0.2.2:{port}"
            )).await?;
            if revoked.exit_code == 0 {
                return Err("revoked host service remained reachable with Internet enabled".into());
            }
            {
                let processes = runtime.vms.lock().await;
                processes.get("internet-test").and_then(|process| process.internet.as_ref())
                    .ok_or("MicroVM filter disappeared")?.set_local_services(&[port])?;
            }
            let published = runtime.execute_micro_vm_command("internet-test", &format!(
                "wget -T 3 -qO- http://10.0.2.2:{port}"
            )).await?;
            if published.exit_code != 0 || published.stdout != "OK" {
                return Err(format!("explicit local service publication failed: {published:?}"));
            }
            {
                let processes = runtime.vms.lock().await;
                processes.get("internet-test").and_then(|process| process.internet.as_ref())
                    .ok_or("MicroVM filter disappeared")?.set_local_services(&[])?;
            }
            let unpublished = runtime.execute_micro_vm_command("internet-test", &format!(
                "wget -T 2 -qO- http://10.0.2.2:{port}"
            )).await?;
            if unpublished.exit_code == 0 {
                return Err("removed local service publication remained reachable".into());
            }
            runtime.vm_action("internet-test", "pause").await?;
            runtime.update_vm_internet("internet-test", false).await?;
            runtime.vm_action("internet-test", "resume").await?;
            let blocked = runtime
                .execute_micro_vm_command(
                    "internet-test",
                    "wget -T 3 -qO- http://example.com",
                )
                .await?;
            if blocked.exit_code == 0 {
                return Err("paused policy change was not enforced".into());
            }
            runtime.vm_action("internet-test", "stop").await?;
            runtime
                .start_micro_vm_with_network(
                    "internet-test",
                    &vm.disk_path,
                    &vm.source_path,
                    &policy,
                    false,
                )
                .await?;
            let blocked = runtime
                .execute_micro_vm_command(
                    "internet-test",
                    "wget -T 3 -qO- http://example.com",
                )
                .await?;
            if blocked.exit_code == 0 {
                return Err("offline boot leaked internet traffic".into());
            }
            Ok(())
        }
        .await;
        runtime.shutdown_all().await;
        http.abort();
        result
    }
}
