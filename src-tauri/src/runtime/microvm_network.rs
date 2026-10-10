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

pub(super) struct MicroVmNetwork {
    enabled: Arc<RwLock<bool>>,
    host: Arc<std::sync::Mutex<HostPolicy>>,
    failed: Arc<AtomicBool>,
    connected: Arc<AtomicU8>,
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
        let mut result = Self {
            enabled: Arc::new(RwLock::new(enabled)),
            host: Arc::new(std::sync::Mutex::new(HostPolicy { host_addresses: host_addresses(), ..HostPolicy::default() })),
            failed: Arc::new(AtomicBool::new(false)),
            connected: Arc::new(AtomicU8::new(0)),
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
                        let allowed = host.lock().map_err(|_| "VM host policy unavailable")?
                            .allows(&packet, direction == "rx", *enabled);
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
        if !grants.iter().any(|grant| grant.ptr_eq(&lifetime)) { grants.push(lifetime); }
        Ok(())
    }
    pub fn set_local_services(&self, ports: &[u16]) -> Result<(), String> {
        if ports.len() > 4096 || ports.contains(&0) { return Err("Invalid VM local service ports".into()); }
        self.host.lock().map_err(|_| "VM host policy unavailable")?.local_services = ports.iter().copied().collect();
        Ok(())
    }
    pub async fn set_enabled(&self, enabled: bool) -> Result<(), String> {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        while self.connected.load(Ordering::Acquire) < 2 {
            if self.tasks.iter().any(|task| task.is_finished()) || tokio::time::Instant::now() >= deadline {
                return Err("VM network filter did not connect. Restart this environment.".into());
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        if self.failed.load(Ordering::Acquire) || self.tasks.iter().any(|task| task.is_finished()) {
            return Err("MicroVM network filter stopped. Restart this environment.".into());
        }
        // Wait for in-flight writes before acknowledging a disconnected cable.
        *self.enabled.write().await = enabled;
        self.host.lock().map_err(|_| "VM host policy unavailable")?.host_addresses = host_addresses();
        Ok(())
    }
}

fn active(grant: &Weak<AtomicBool>) -> bool {
    grant.upgrade().is_some_and(|value| value.load(Ordering::Acquire))
}
fn host_addresses() -> HashSet<[u8; 4]> {
    sysinfo::Networks::new_with_refreshed_list().values().flat_map(|network| network.ip_networks())
        .filter_map(|network| match network.addr { std::net::IpAddr::V4(ip) => Some(ip.octets()), _ => None }).collect()
}

#[derive(Default)]
struct HostPolicy {
    host_addresses: HashSet<[u8; 4]>,
    services: HashMap<u16, Vec<Weak<AtomicBool>>>,
    local_services: HashSet<u16>,
    // Only SYNs received from QEMU's trusted host-forwarding direction create
    // reply grants. A guest choosing source port 7443 cannot create a grant.
    replies: HashMap<([u8; 4], [u8; 4], u16, u16), Instant>,
}
impl HostPolicy {
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
            if u16::from_be_bytes([packet[20], packet[21]]) & 0x3fff != 0 { return false; }
            let peer = if outbound {
                &packet[30..34]
            } else {
                &packet[26..30]
            };
            if outbound {
                let source = &packet[26..30];
                if source != [0, 0, 0, 0]
                    && !(source[..3] == [10, 0, 2] && (4..=254).contains(&source[3])) {
                    return false;
                }
            }
            let peer_address: [u8; 4] = peer.try_into().unwrap();
            if peer == [10, 0, 2, 2] || self.host_addresses.contains(&peer_address) {
                let transport = &packet[14 + header..14 + total];
                // Preserve gateway diagnostics without granting host sockets.
                if peer == [10, 0, 2, 2] && internet && packet[23] == 1 && transport.len() >= 8 {
                    return transport[1] == 0 && transport[0] == if outbound { 8 } else { 0 };
                }
                if packet[23] == 17 && transport.len() >= 8 {
                    let source = u16::from_be_bytes([transport[0], transport[1]]);
                    let target = u16::from_be_bytes([transport[2], transport[3]]);
                    return (outbound && source == 68 && target == 67)
                        || (!outbound && source == 67 && target == 68);
                }
                if packet[23] != 6 || transport.len() < 20 { return false; }
                let tcp_header = usize::from(transport[12] >> 4) * 4;
                if tcp_header < 20 || transport.len() < tcp_header { return false; }
                let source = u16::from_be_bytes([transport[0], transport[1]]);
                let target = u16::from_be_bytes([transport[2], transport[3]]);
                let (guest, guest_port, host_port) = if outbound {
                    (packet[26..30].try_into().unwrap(), source, target)
                } else { (packet[30..34].try_into().unwrap(), target, source) };
                if self.local_services.contains(&host_port)
                    || self.services.get(&host_port).is_some_and(|grants| grants.iter().any(active)) {
                    return true;
                }
                let now = Instant::now();
                self.replies.retain(|_, touched| now.duration_since(*touched) < Duration::from_secs(300));
                let key = (guest, peer_address, guest_port, host_port);
                let flags = transport[13];
                if !outbound && flags & 0x12 == 0x02 && self.replies.len() < 4096 {
                    self.replies.insert(key, now);
                    return true;
                }
                // A new guest-initiated SYN is never a reply, even when its
                // chosen tuple matches an existing host-forwarded session.
                if outbound && flags & 0x12 == 0x02 { return false; }
                if let Some(touched) = self.replies.get_mut(&key) {
                    *touched = now;
                    if flags & 0x04 != 0 { self.replies.remove(&key); }
                    return true;
                }
                return false;
            }
            // SLIRP's virtual DNS is the only other service on its internal
            // subnet. Do not let aliases or loopback/link-local targets become
            // another route to the host control plane or cloud metadata.
            if peer[..3] == [10, 0, 2] {
                let transport = &packet[14 + header..14 + total];
                let port_offset = if outbound { 2 } else { 0 };
                return internet && peer[3] == 3 && matches!(packet[23], 6 | 17)
                    && transport.len() >= 4
                    && u16::from_be_bytes([transport[port_offset], transport[port_offset + 1]]) == 53;
            }
            if internet && peer[0] != 0 && peer[0] != 127 && peer[..2] != [169, 254] && peer[0] < 224 {
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
        let mut policy = HostPolicy::default();
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
        let mut policy = HostPolicy::default();
        policy.host_addresses.insert([192, 168, 1, 10]);
        for internet in [false, true] {
            for port in [22, 7443, 5900, 32123] {
                assert!(!policy.allows(&tcp(guest, host, 7443, port, 2), true, internet));
                assert!(!policy.allows(&tcp(guest, host, 7443, port, 0x10), true, internet));
            }
            assert!(!policy.allows(&tcp(guest, [192, 168, 1, 10], 40000, 8080, 2), true, internet));
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
    #[tokio::test]
    async fn explicit_host_grants_end_with_the_service_and_do_not_authorize_other_ports() {
        let network = MicroVmNetwork::new(true, 0).await.unwrap();
        let active = Arc::new(AtomicBool::new(true));
        network.grant_host_service(12345, Arc::downgrade(&active)).unwrap();
        let guest = [10, 0, 2, 15];
        let host = [10, 0, 2, 2];
        {
            let mut policy = network.host.lock().unwrap();
            assert!(policy.allows(&tcp(guest, host, 40000, 12345, 2), true, true));
            assert!(!policy.allows(&tcp(guest, host, 40000, 12346, 2), true, true));
        }
        active.store(false, Ordering::Release);
        assert!(!network.host.lock().unwrap().allows(&tcp(guest, host, 40000, 12345, 0x10), true, true));
        assert!(network.grant_host_service(12345, Arc::downgrade(&active)).is_err());
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
            runtime.grant_qemu_host_service("internet-test", port, Arc::downgrade(&host_service)).await?;
            for enabled in [false, true, false, true] {
                runtime.update_vm_internet("internet-test", enabled).await?;
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
