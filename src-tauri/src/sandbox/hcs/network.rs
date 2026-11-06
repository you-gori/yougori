//! A private endpoint on an existing Windows NAT switch. Never creates a switch,
//! changes a physical adapter, installs a bridge, or changes host DNS/routes.
use crate::foundation::process::ProcessIdentity;
use serde_json::{json, Value};
use std::{ffi::c_void, ptr};
use windows_sys::{
    core::GUID,
    Win32::System::{Com::CoTaskMemFree, HostComputeNetwork::*},
};

// A NAT gateway is not necessarily a DNS proxy (notably the WSL NAT network).
// Read the active host adapters' resolver configuration without changing it.
fn host_dns() -> Result<Vec<String>, String> {
    use windows_sys::Win32::{
        Foundation::ERROR_BUFFER_OVERFLOW,
        NetworkManagement::{IpHelper::*, Ndis::IfOperStatusUp},
        Networking::WinSock::{AF_INET, SOCKADDR_IN},
    };
    let mut size = 16_384u32;
    for _ in 0..3 {
        if size > 1 << 20 {
            return Err("Windows adapter information exceeds its bound".into());
        }
        // The native structure starts with a u64 and requires aligned storage.
        let mut buffer = vec![0u64; (size as usize).div_ceil(8)];
        let first = buffer.as_mut_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
        let code = unsafe {
            GetAdaptersAddresses(
                AF_INET as u32,
                GAA_FLAG_INCLUDE_GATEWAYS,
                ptr::null(),
                first,
                &mut size,
            )
        };
        if code == ERROR_BUFFER_OVERFLOW {
            continue;
        }
        if code != 0 {
            return Err(format!("Cannot read Windows DNS settings: {code}"));
        }
        let mut addresses = Vec::new();
        let mut next = first;
        while !next.is_null() {
            // All pointers belong to the buffer populated by GetAdaptersAddresses.
            let adapter = unsafe { &*next };
            if adapter.OperStatus == IfOperStatusUp {
                let mut server = adapter.FirstDnsServerAddress;
                while !server.is_null() {
                    let dns = unsafe { &*server };
                    if !dns.Address.lpSockaddr.is_null()
                        && dns.Address.iSockaddrLength >= std::mem::size_of::<SOCKADDR_IN>() as i32
                    {
                        let socket = unsafe { &*(dns.Address.lpSockaddr.cast::<SOCKADDR_IN>()) };
                        if socket.sin_family == AF_INET {
                            let address = std::net::Ipv4Addr::from(
                                unsafe { socket.sin_addr.S_un.S_addr }.to_ne_bytes(),
                            );
                            if !address.is_loopback()
                                && !address.is_unspecified()
                                && !address.is_multicast()
                            {
                                addresses.push((
                                    adapter.FirstGatewayAddress.is_null(),
                                    adapter.Ipv4Metric,
                                    address,
                                ));
                            }
                        }
                    }
                    server = dns.Next;
                }
            }
            next = adapter.Next;
        }
        addresses.sort();
        let mut servers = Vec::new();
        for (_, _, address) in addresses {
            let address = address.to_string();
            if !servers.contains(&address) {
                servers.push(address);
            }
            if servers.len() == 4 {
                break;
            }
        }
        if servers.is_empty() {
            return Err(
                "No reachable IPv4 DNS resolver is configured on an active Windows network.".into(),
            );
        }
        return Ok(servers);
    }
    Err("Windows networking changed while reading its DNS settings; try again.".into())
}

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(Some(0)).collect()
}
fn guid(value: &str) -> Result<GUID, String> {
    let value: uuid::Uuid = value.parse().map_err(|e: uuid::Error| e.to_string())?;
    let (data1, data2, data3, data4) = value.as_fields();
    Ok(GUID {
        data1,
        data2,
        data3,
        data4: *data4,
    })
}
unsafe fn take(text: *mut u16) -> String {
    if text.is_null() {
        return String::new();
    }
    let mut length = 0;
    while length < 4 * 1024 * 1024 && unsafe { *text.add(length) } != 0 {
        length += 1;
    }
    let value = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(text, length) });
    unsafe { CoTaskMemFree(text.cast()) };
    value
}
fn check(code: i32, error: *mut u16) -> Result<(), String> {
    let error = unsafe { take(error) };
    if code < 0 {
        Err(format!(
            "Windows VM network 0x{:08X}: {}",
            code as u32,
            error.chars().take(1000).collect::<String>()
        ))
    } else {
        Ok(())
    }
}
fn query(call: impl FnOnce(*mut *mut u16, *mut *mut u16) -> i32) -> Result<Value, String> {
    let (mut result, mut error) = (ptr::null_mut(), ptr::null_mut());
    let code = call(&mut result, &mut error);
    let text = unsafe { take(result) };
    check(code, error)?;
    serde_json::from_str(&text).map_err(|e| e.to_string())
}
struct Network(*mut c_void);
impl Drop for Network {
    fn drop(&mut self) {
        unsafe { HcnCloseNetwork(self.0) };
    }
}

/// WSL's Hyper-V firewall VM creator ({40E0AC32-46A5-438A-A0B2-2B479E8F2E90}).
/// WSL's NAT network can enforce the Hyper-V firewall: a port on it passes traffic
/// only under the rules of the VM creator its endpoint names, and an endpoint that
/// names none gets no outbound access. WSL tags its own endpoints this way
/// (microsoft/WSL, src/windows/common/NatNetworking.cpp). Naming WSL's creator applies
/// the firewall settings this PC already has for WSL (by default: outbound allowed,
/// inbound blocked) and adds no firewall rule or setting.
const WSL_FIREWALL_CREATOR: &str = "40E0AC32-46A5-438A-A0B2-2B479E8F2E90";

fn enforces_hyperv_firewall(network: &Value) -> bool {
    network["Name"]
        .as_str()
        .is_some_and(|name| name.to_ascii_lowercase().contains("hyper-v firewall"))
}

/// The endpoint document for `network`. A network that enforces the Hyper-V firewall
/// gets WSL's endpoint policy (schema 2.16, as WSL uses); others keep the plain 2.0
/// document, so older Windows builds are unaffected.
fn endpoint_settings(name: &str, network: &Value) -> Value {
    if enforces_hyperv_firewall(network) {
        json!({
            "SchemaVersion":{"Major":2,"Minor":16},
            "Name":name,
            "HostComputeNetwork":network["ID"],
            "Policies":[{"Type":"Firewall","Settings":{"VmCreatorId":WSL_FIREWALL_CREATOR,"PolicyFlags":0}}],
        })
    } else {
        json!({"SchemaVersion":{"Major":2,"Minor":0},"Name":name,"HostComputeNetwork":network["ID"]})
    }
}
pub struct Endpoint {
    pub id: String,
    pub properties: Value,
    handle: *mut c_void,
    removed: bool,
}
impl Endpoint {
    pub fn create(vm: &str, owner: ProcessIdentity) -> Result<Self, String> {
        reap_orphans()?;
        let query_text = wide(r#"{"SchemaVersion":{"Major":2,"Minor":0}}"#);
        let ids =
            query(|out, error| unsafe { HcnEnumerateNetworks(query_text.as_ptr(), out, error) })?;
        let mut candidates = Vec::new();
        for id in ids.as_array().ok_or("Windows network list is invalid")? {
            let id = guid(id.as_str().ok_or("Windows network identity is invalid")?)?;
            let (mut handle, mut error) = (ptr::null_mut(), ptr::null_mut());
            let code = unsafe { HcnOpenNetwork(&id, &mut handle, &mut error) };
            // A network may disappear during enumeration; the others are still usable.
            if check(code, error).is_err() {
                continue;
            }
            let network = Network(handle);
            let Ok(properties) = query(|out, error| unsafe {
                HcnQueryNetworkProperties(network.0, query_text.as_ptr(), out, error)
            }) else {
                continue;
            };
            if matches!(properties["Type"].as_str(), Some("ICS" | "NAT")) {
                candidates.push((network, properties));
            }
        }
        // Prefer a NAT network without the Hyper-V firewall: it needs no creator tag.
        candidates.sort_by_key(|(_, properties)| enforces_hyperv_firewall(properties));
        if let Some((network, properties)) = candidates.into_iter().next() {
            let endpoint_id = uuid::Uuid::new_v4().to_string();
            let settings = endpoint_settings(
                &format!("yougori-hcs-{vm}-{}-{}", owner.pid, owner.start_time_ticks),
                &properties,
            );
            let (mut handle, mut error) = (ptr::null_mut(), ptr::null_mut());
            let code = unsafe {
                HcnCreateEndpoint(
                    network.0,
                    &guid(&endpoint_id)?,
                    wide(&settings.to_string()).as_ptr(),
                    &mut handle,
                    &mut error,
                )
            };
            check(code, error).map_err(|error| {
                format!(
                    "{error} (network {})",
                    properties["Name"].as_str().unwrap_or("unnamed")
                )
            })?;
            let mut endpoint = Self {
                id: endpoint_id,
                properties: Value::Null,
                handle,
                removed: false,
            };
            endpoint.properties = query(|out, error| unsafe {
                HcnQueryEndpointProperties(endpoint.handle, query_text.as_ptr(), out, error)
            })?;
            endpoint.properties["Dns"] = json!({"ServerList":host_dns()?});
            endpoint.boot()?;
            return Ok(endpoint);
        }
        Err("No Windows NAT network is available yet. Windows creates one when WSL starts: open any WSL distribution once, then start this VM again. Or turn outgoing internet off and use selected online requests.".into())
    }
    pub fn adapter(&self) -> Value {
        json!({"EndpointId":self.id,"MacAddress":self.properties["MacAddress"]})
    }
    pub fn boot(&self) -> Result<Value, String> {
        let address = self.properties["IpConfigurations"][0]["IpAddress"]
            .as_str()
            .ok_or("Windows did not assign an IPv4 address")?;
        address
            .parse::<std::net::Ipv4Addr>()
            .map_err(|_| "Windows did not assign IPv4")?;
        let prefix = self.properties["IpConfigurations"][0]["PrefixLength"]
            .as_u64()
            .filter(|n| *n > 0 && *n < 32)
            .ok_or("Windows did not assign an IPv4 prefix")?;
        let gateway = self.properties["Routes"]
            .as_array()
            .and_then(|routes| {
                routes
                    .iter()
                    .find(|route| route["DestinationPrefix"] == "0.0.0.0/0")
            })
            .and_then(|route| route["NextHop"].as_str())
            .ok_or("Windows did not assign a default route")?;
        gateway
            .parse::<std::net::Ipv4Addr>()
            .map_err(|_| "Windows did not assign an IPv4 gateway")?;
        let dns = self.properties["Dns"]["ServerList"]
            .as_array()
            .map(|values| {
                values
                    .iter()
                    .filter_map(Value::as_str)
                    .filter(|ip| ip.parse::<std::net::Ipv4Addr>().is_ok())
                    .collect::<Vec<_>>()
            })
            .filter(|v| !v.is_empty())
            .ok_or("Windows did not provide a usable IPv4 DNS resolver")?;
        Ok(json!({"address":format!("{address}/{prefix}"),"gateway":gateway,"dns":dns}))
    }
    pub fn remove(&mut self) -> Result<(), String> {
        if self.removed {
            return Ok(());
        }
        if !self.handle.is_null() {
            unsafe { HcnCloseEndpoint(self.handle) };
            self.handle = ptr::null_mut();
        }
        let mut error = ptr::null_mut();
        let code = unsafe { HcnDeleteEndpoint(&guid(&self.id)?, &mut error) };
        check(code, error)?;
        self.removed = true;
        Ok(())
    }
}

fn endpoint_owner(name: &str) -> Option<(&str, ProcessIdentity)> {
    let mut parts = name.strip_prefix("yougori-hcs-")?.rsplitn(3, '-');
    let start_time_ticks = parts.next()?.parse().ok()?;
    let pid = parts.next()?.parse().ok()?;
    let vm = parts.next()?;
    uuid::Uuid::parse_str(vm).ok()?;
    Some((
        vm,
        ProcessIdentity {
            pid,
            start_time_ticks,
        },
    ))
}

// HCS closes the VM on a helper crash. HCN endpoints have independent lifetimes.
// Reclaim only our exact naming contract, with a dead owner (creation time as
// well as PID) AND an absent compute system. A concurrent launch has a live
// owner even before it creates its compute system, so it cannot be swept.
fn reap_orphans() -> Result<(), String> {
    let q = wide(r#"{"SchemaVersion":{"Major":2,"Minor":0}}"#);
    let ids = query(|out, error| unsafe { HcnEnumerateEndpoints(q.as_ptr(), out, error) })?;
    for id in ids.as_array().ok_or("Windows endpoint list is invalid")? {
        let id = guid(id.as_str().ok_or("Windows endpoint identity is invalid")?)?;
        let (mut handle, mut error) = (ptr::null_mut(), ptr::null_mut());
        let code = unsafe { HcnOpenEndpoint(&id, &mut handle, &mut error) };
        if check(code, error).is_err() {
            continue;
        } // An endpoint may end during enumeration.
        let properties = query(|out, error| unsafe {
            HcnQueryEndpointProperties(handle, q.as_ptr(), out, error)
        });
        unsafe { HcnCloseEndpoint(handle) };
        let Ok(properties) = properties else {
            continue;
        };
        let Some((vm, owner)) = properties["Name"].as_str().and_then(endpoint_owner) else {
            continue;
        };
        if !matches!(owner.running(), Ok(false)) || super::api::wait_absent(vm).is_err() {
            continue;
        }
        // Best effort: one stale endpoint that Windows will not delete must not block
        // every later launch. It is retried on the next launch.
        let mut error = ptr::null_mut();
        let _ = check(unsafe { HcnDeleteEndpoint(&id, &mut error) }, error);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn a_hyperv_firewall_network_gets_wsls_creator_policy() {
        let network = json!({"ID":"5f2a","Name":"WSL (Hyper-V firewall)","Type":"ICS"});
        let settings = endpoint_settings("yougori-hcs-x", &network);
        assert_eq!(settings["HostComputeNetwork"], "5f2a");
        assert_eq!(settings["Name"], "yougori-hcs-x");
        assert_eq!(settings["SchemaVersion"], json!({"Major":2,"Minor":16}));
        assert_eq!(
            settings["Policies"],
            json!([{"Type":"Firewall","Settings":{"VmCreatorId":"40E0AC32-46A5-438A-A0B2-2B479E8F2E90","PolicyFlags":0}}])
        );
        assert!(WSL_FIREWALL_CREATOR.parse::<uuid::Uuid>().is_ok());
    }

    #[test]
    fn other_networks_keep_the_plain_endpoint_and_are_preferred() {
        let plain = json!({"ID":"7c1d","Name":"Default Switch","Type":"ICS"});
        let settings = endpoint_settings("yougori-hcs-x", &plain);
        assert!(settings.get("Policies").is_none());
        assert_eq!(settings["SchemaVersion"], json!({"Major":2,"Minor":0}));
        let mut networks = vec![json!({"Name":"WSL (Hyper-V firewall)"}), plain];
        networks.sort_by_key(enforces_hyperv_firewall);
        assert_eq!(networks[0]["Name"], "Default Switch");
        assert!(!enforces_hyperv_firewall(&json!({"Type":"NAT"})));
    }

    #[test]
    fn orphan_cleanup_needs_our_full_process_identity_and_vm_uuid() {
        let vm = uuid::Uuid::new_v4().to_string();
        let name = format!("yougori-hcs-{vm}-42-12345");
        assert_eq!(
            endpoint_owner(&name),
            Some((
                vm.as_str(),
                ProcessIdentity {
                    pid: 42,
                    start_time_ticks: 12345
                }
            ))
        );
        for name in [
            format!("yougori-hcs-{vm}"),
            format!("other-{vm}-42-12345"),
            "yougori-hcs-not-a-vm-42-12345".into(),
        ] {
            assert!(endpoint_owner(&name).is_none());
        }
    }
}
impl Drop for Endpoint {
    fn drop(&mut self) {
        let _ = self.remove();
    }
}
