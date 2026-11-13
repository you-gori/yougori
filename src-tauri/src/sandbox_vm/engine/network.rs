//! Validate network intent before creating resources. The current NAT backend
//! supports outgoing IPv4 traffic, not unsolicited all-port ingress. Every frame of a
//! VM's network card passes the host's filter (`sandbox::qemu_host::network_filter`):
//! `internet` reaches the public internet only, never this computer or its networks;
//! `targets` reaches the named hosts and ports alone, resolved on this computer here, at
//! launch. A host named by its name may share its addresses with other sites, so each
//! HTTPS and HTTP connection there must ask for a named host; other protocols name no
//! site and reach whatever answers at the address and port.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use serde_json::Value;

use crate::sandbox::backend::{NetworkTarget, MAX_NETWORK_TARGETS};
use crate::security::network::cloud_management_peer;

/// How long one name may take to resolve on this computer.
const RESOLVE_TIMEOUT: Duration = Duration::from_secs(10);
/// Most addresses one named host keeps (every one is equally allowed).
const MAX_TARGET_ADDRESSES: usize = 16;
const TARGETS_SHAPE: &str = "targets must be a list of 1 to 64 hosts such as \"staging.example.com:443\" or \"192.168.1.50\" (a host alone is every port of it).";
const THIS_COMPUTER: &str = "A VM never reaches this computer's own services; name another computer.";

pub(super) fn launch_internet(params: &Value) -> Result<bool, String> {
    let flag = |name: &str| -> Result<bool, String> {
        match params.get(name) {
            None | Some(Value::Null) => Ok(false),
            Some(Value::Bool(value)) => Ok(*value),
            _ => Err(format!("{name} must be true or false.")),
        }
    };
    let internet = flag("internet")?;
    if flag("incoming")? {
        return Err("Incoming access to all VM ports is not supported by this backend. You can publish individual apps instead. No VM or host network changes were made for this request.".into());
    }
    let routes = params.get("routes").is_some_and(|value| !value.is_null());
    if internet && routes {
        return Err("Choose unrestricted outgoing internet access or selected online requests, not both.".into());
    }
    if params.get("targets").is_some_and(|value| !value.is_null()) {
        if internet {
            return Err("Choose the whole internet or chosen targets, not both: with targets the VM reaches those alone.".into());
        }
        if routes {
            return Err("Choose chosen targets or selected online requests, not both.".into());
        }
        if params.get("gpu").and_then(Value::as_bool) == Some(true) {
            return Err("Chosen targets are not available for GPU VMs yet: a GPU VM's network does not pass Yougori's filter. Launch it without gpu, or without targets.".into());
        }
    }
    Ok(internet)
}

/// One target a launch names, as checked: the host (a lowercase DNS name or an IPv4
/// address), the address when it is one, and its TCP ports (`None`: every port).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct TargetRequest {
    pub host: String,
    pub address: Option<Ipv4Addr>,
    pub ports: Option<BTreeSet<u16>>,
}

/// `targets`: 1 to 64 entries `host:port`, or a host alone for every port of it. A host is a
/// DNS name (a single label only with a port) or an IPv4 address, never this computer
/// (localhost, 127.x.x.x), "this network" (0.x.x.x), link-local or cloud management space,
/// multicast or broadcast, or the VM's own network (10.0.2.0/24, which leads back to this
/// computer). A host named twice keeps every port it was named with. `None` without targets.
pub(super) fn launch_targets(params: &Value) -> Result<Option<Vec<TargetRequest>>, String> {
    let entries = match params.get("targets") {
        None | Some(Value::Null) => return Ok(None),
        Some(Value::Array(entries)) if (1..=MAX_NETWORK_TARGETS).contains(&entries.len()) => entries,
        Some(_) => return Err(TARGETS_SHAPE.into()),
    };
    let mut requests: Vec<TargetRequest> = Vec::new();
    for entry in entries {
        let Value::String(text) = entry else {
            return Err(TARGETS_SHAPE.into());
        };
        let (host, address, port) = target_entry(text)?;
        let ports = port.map(|port| BTreeSet::from([port]));
        match requests.iter_mut().find(|request| request.host == host) {
            Some(request) => match (&mut request.ports, ports) {
                (Some(known), Some(more)) => known.extend(more),
                (known, _) => *known = None,
            },
            None => requests.push(TargetRequest { host, address, ports }),
        }
    }
    Ok(Some(requests))
}

/// One entry: its host, the host's address when it is one, and its port.
fn target_entry(raw: &str) -> Result<(String, Option<Ipv4Addr>, Option<u16>), String> {
    let shown = raw.trim();
    let text = shown.to_ascii_lowercase();
    if text.contains("://") {
        return Err(format!(
            "{shown} is a web address: name its host and port instead, such as staging.example.com:443."
        ));
    }
    let parts: Vec<&str> = text.split(':').collect();
    let (host, port) = match parts[..] {
        [host] => (host, None),
        [host, port] => {
            let number = (!port.is_empty()
                && port.len() <= 5
                && port.bytes().all(|byte| byte.is_ascii_digit())
                && !port.starts_with('0'))
            .then(|| port.parse::<u16>().ok())
            .flatten();
            match number {
                Some(number) => (host, Some(number)),
                None => return Err(format!("{shown} has no valid port (1 to 65535).")),
            }
        }
        _ => {
            return Err(format!(
                "{shown} is not a host such as staging.example.com:443 (IPv6 addresses are not taken)."
            ))
        }
    };
    let octets: Vec<&str> = host.split('.').collect();
    if octets.len() == 4 && octets.iter().all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit())) {
        let address: Ipv4Addr = octets
            .iter()
            .all(|part| part.len() <= 3 && (part.len() == 1 || !part.starts_with('0')))
            .then(|| host.parse().ok())
            .flatten()
            .ok_or_else(|| format!("{shown} is not an IPv4 address."))?;
        if let Some(problem) = never_reached(address) {
            return Err(format!("{shown} {problem}"));
        }
        return Ok((address.to_string(), Some(address), port));
    }
    let name = host.strip_suffix('.').unwrap_or(host);
    let labels: Vec<&str> = name.split('.').collect();
    let label_ok = |label: &&str| {
        (1..=63).contains(&label.len())
            && label.bytes().all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
            && !label.starts_with('-')
            && !label.ends_with('-')
    };
    let last = labels.last().copied().unwrap_or("");
    if last == "localhost" {
        return Err(format!("{shown} is this computer. {THIS_COMPUTER}"));
    }
    if !(1..=253).contains(&name.len())
        || !labels.iter().all(label_ok)
        || (labels.len() == 1 && port.is_none())
        || last.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(format!(
            "{shown} is not a host such as staging.example.com or staging.example.com:443."
        ));
    }
    Ok((name.to_owned(), None, port))
}

/// Why no VM ever reaches `address`, whoever names it; `None` for an address a VM may be
/// held to.
fn never_reached(address: Ipv4Addr) -> Option<String> {
    let octets = address.octets();
    if octets[0] == 127 {
        return Some(format!("is this computer. {THIS_COMPUTER}"));
    }
    if octets[..3] == [10, 0, 2] {
        return Some("is in the VM's own network (10.0.2.0/24), which leads back to this computer. Name another address.".into());
    }
    if octets[0] == 0 || octets[0] >= 224 {
        return Some("is not an address of a computer to test.".into());
    }
    if cloud_management_peer(octets) {
        return Some("is a link-local or cloud management address, which a VM never reaches.".into());
    }
    None
}

/// Whether `address` is in private, shared or reserved space (the person's networks, VPNs,
/// other VMs on this computer, benchmarking and documentation space): no public address.
fn private(address: Ipv4Addr) -> bool {
    let octets = address.octets();
    crate::security::network::private_peer(octets) || crate::sandbox::qemu_host::network_filter::reserved(octets)
}

/// The targets a VM's card is held to: each named host with the addresses `resolved` gave
/// its name on this computer (an address names itself) and its ports. Refused, with a plain
/// reason, when a host is this computer (`this_computer`: its addresses now) or leads to it,
/// leads to space no VM reaches, or is a name that leads to a private address not also
/// named itself (a public name never opens the person's own network by itself).
pub(super) fn resolve_targets(
    requests: &[TargetRequest],
    resolved: &HashMap<String, Result<Vec<Ipv4Addr>, String>>,
    this_computer: &HashSet<[u8; 4]>,
) -> Result<Vec<NetworkTarget>, String> {
    let named: HashSet<Ipv4Addr> = requests.iter().filter_map(|request| request.address).collect();
    let mut targets = Vec::with_capacity(requests.len());
    for request in requests {
        let ports: Vec<u16> = request.ports.iter().flatten().copied().collect();
        let addresses = match request.address {
            Some(address) => {
                if this_computer.contains(&address.octets()) {
                    return Err(format!("{} is an address of this computer. {THIS_COMPUTER}", request.host));
                }
                vec![address]
            }
            None => {
                let found = match resolved.get(&request.host) {
                    Some(Ok(found)) if !found.is_empty() => found,
                    Some(Err(error)) => {
                        return Err(format!(
                            "{} could not be found from this computer ({error}). Check the name, or name the computer's address instead.",
                            request.host
                        ))
                    }
                    _ => {
                        return Err(format!(
                            "{} has no IPv4 address on this computer. Check the name, or name the computer's address instead.",
                            request.host
                        ))
                    }
                };
                let mut addresses: Vec<Ipv4Addr> = Vec::new();
                for &address in found {
                    if this_computer.contains(&address.octets()) || address.octets()[0] == 127 {
                        return Err(format!("{} leads to this computer ({address}). {THIS_COMPUTER}", request.host));
                    }
                    if never_reached(address).is_some() {
                        return Err(format!("{} leads to {address}, which a VM never reaches.", request.host));
                    }
                    if private(address) && !named.contains(&address) {
                        let example = ports.first().map_or_else(|| address.to_string(), |port| format!("{address}:{port}"));
                        return Err(format!(
                            "{} leads to {address}, an address on a private network. Name {example} too to let the VM reach it.",
                            request.host
                        ));
                    }
                    if !addresses.contains(&address) && addresses.len() < MAX_TARGET_ADDRESSES {
                        addresses.push(address);
                    }
                }
                addresses
            }
        };
        targets.push(NetworkTarget {
            host: request.host.clone(),
            addresses,
            ports,
        });
    }
    Ok(targets)
}

/// [`resolve_targets`] with the names resolved by this computer's resolver now (IPv4 only,
/// each within [`RESOLVE_TIMEOUT`]) and this computer's addresses as it holds them now.
pub(super) async fn resolve_on_this_computer(requests: Vec<TargetRequest>) -> Result<Vec<NetworkTarget>, String> {
    let names: Vec<String> = requests
        .iter()
        .filter(|request| request.address.is_none())
        .map(|request| request.host.clone())
        .collect();
    let lookups = names.iter().map(|name| async move {
        let found = match tokio::time::timeout(RESOLVE_TIMEOUT, tokio::net::lookup_host((name.as_str(), 0))).await {
            Err(_) => Err(format!("no answer within {} seconds", RESOLVE_TIMEOUT.as_secs())),
            Ok(Err(error)) => Err(error.to_string()),
            Ok(Ok(addresses)) => Ok(addresses
                .filter_map(|address| match address.ip() {
                    IpAddr::V4(address) => Some(address),
                    IpAddr::V6(_) => None,
                })
                .collect()),
        };
        (name.clone(), found)
    });
    let resolved: HashMap<String, Result<Vec<Ipv4Addr>, String>> =
        futures_util::future::join_all(lookups).await.into_iter().collect();
    let this_computer = crate::runtime::host_ipv4_addresses().map_err(|error| {
        format!("This computer's own addresses could not be read, so the targets could not be checked and nothing was started: {error}")
    })?;
    resolve_targets(&requests, &resolved, &this_computer)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn incoming_all_is_never_silently_downgraded_to_outgoing_or_published_apps() {
        for params in [
            json!({"incoming":true}),
            json!({"incoming":true,"internet":false}),
            json!({"incoming":true,"internet":true}),
            json!({"incoming":true,"publish":"web=3000"}),
        ] {
            assert!(launch_internet(&params).unwrap_err().contains("not supported"));
        }
    }

    #[test]
    fn absent_or_disabled_incoming_does_not_change_outgoing_permission() {
        for incoming in [Value::Null, json!(false)] {
            assert!(!launch_internet(&json!({"incoming":incoming})).unwrap());
            assert!(launch_internet(&json!({"incoming":incoming,"internet":true})).unwrap());
        }
        assert!(!launch_internet(&json!({})).unwrap());
        assert!(!launch_internet(&json!({"internet":false})).unwrap());
    }

    #[test]
    fn malformed_switches_and_conflicting_routes_are_refused() {
        for name in ["internet", "incoming"] {
            for value in [json!("false"), json!(1), json!([]), json!({})] {
                let params = Value::Object([(name.into(), value)].into_iter().collect());
                assert_eq!(launch_internet(&params), Err(format!("{name} must be true or false.")));
            }
        }
        assert!(launch_internet(&json!({"internet":true,"routes":[]})).is_err());
        assert!(launch_internet(&json!({"internet":true,"routes":null})).unwrap());
        assert!(!launch_internet(&json!({"internet":false,"routes":[{}]})).unwrap());
    }

    #[test]
    fn targets_exclude_the_whole_internet_routes_and_gpu_vms() {
        let targets = json!(["staging.example.com:443"]);
        assert!(launch_internet(&json!({"internet":true,"targets":targets})).unwrap_err().contains("not both"));
        assert!(launch_internet(&json!({"routes":[{}],"targets":targets})).unwrap_err().contains("not both"));
        assert!(launch_internet(&json!({"gpu":true,"targets":targets})).unwrap_err().contains("GPU"));
        // Targets alone ask for no internet: the card they add is held to them.
        assert!(!launch_internet(&json!({"targets":targets})).unwrap());
        assert!(!launch_internet(&json!({"internet":false,"targets":targets})).unwrap());
        assert!(launch_internet(&json!({"internet":true,"targets":null})).unwrap());
    }

    fn requests(entries: Value) -> Vec<TargetRequest> {
        launch_targets(&json!({"targets": entries})).unwrap().unwrap()
    }

    fn refused(entry: &str) -> String {
        launch_targets(&json!({"targets": [entry]})).unwrap_err()
    }

    #[test]
    fn targets_are_hosts_with_their_ports_each_host_once() {
        assert_eq!(launch_targets(&json!({})).unwrap(), None);
        assert_eq!(launch_targets(&json!({"targets":null})).unwrap(), None);
        let checked = requests(json!([
            "Staging.MyCompany.com:443",
            "192.168.1.50:8080",
            "staging.mycompany.com.:8443",
            "jenkins:8080",
            "10.1.2.3",
            "10.1.2.3:22",
        ]));
        assert_eq!(
            checked,
            vec![
                TargetRequest { host: "staging.mycompany.com".into(), address: None, ports: Some(BTreeSet::from([443, 8443])) },
                TargetRequest { host: "192.168.1.50".into(), address: Some(Ipv4Addr::new(192, 168, 1, 50)), ports: Some(BTreeSet::from([8080])) },
                TargetRequest { host: "jenkins".into(), address: None, ports: Some(BTreeSet::from([8080])) },
                // Named alone: every port, whatever else it was named with.
                TargetRequest { host: "10.1.2.3".into(), address: Some(Ipv4Addr::new(10, 1, 2, 3)), ports: None },
            ]
        );
        for shape in [json!("a.example.com"), json!([]), json!([1]), json!({"host":"a.example.com"}), json!(vec!["a.example.com"; 65])] {
            assert_eq!(launch_targets(&json!({"targets": shape})).unwrap_err(), TARGETS_SHAPE);
        }
    }

    #[test]
    fn this_computer_and_space_no_vm_reaches_are_refused_plainly() {
        for (entry, reason) in [
            ("localhost:8080", "is this computer"),
            ("app.localhost", "is this computer"),
            ("127.0.0.1:80", "is this computer"),
            ("127.1.2.3", "is this computer"),
            ("10.0.2.2:8080", "VM's own network"),
            ("10.0.2.15", "VM's own network"),
            ("0.0.0.0", "not an address of a computer"),
            ("224.0.0.251", "not an address of a computer"),
            ("255.255.255.255", "not an address of a computer"),
            ("169.254.169.254", "cloud management"),
            ("168.63.129.16:80", "cloud management"),
            ("staging.example.com:0", "no valid port"),
            ("staging.example.com:65536", "no valid port"),
            ("staging.example.com:080", "no valid port"),
            ("staging.example.com:", "no valid port"),
            ("[::1]:80", "IPv6"),
            ("a:b:c", "IPv6"),
            ("192.168.1.300", "not an IPv4 address"),
            ("192.168.01.5", "not an IPv4 address"),
            ("jenkins", "not a host"),
            ("-bad.example.com", "not a host"),
            ("bad_name.example.com", "not a host"),
            ("example.123", "not a host"),
            ("https://staging.example.com", "is a web address"),
        ] {
            let error = refused(entry);
            assert!(error.contains(reason), "{entry}: {error}");
        }
        assert!(refused("localhost:8080").contains("A VM never reaches this computer's own services"));
    }

    fn found(entries: &[(&str, Result<Vec<[u8; 4]>, &str>)]) -> HashMap<String, Result<Vec<Ipv4Addr>, String>> {
        entries
            .iter()
            .map(|(name, result)| {
                let result = match result {
                    Ok(addresses) => Ok(addresses.iter().map(|octets| Ipv4Addr::from(*octets)).collect()),
                    Err(error) => Err((*error).to_owned()),
                };
                ((*name).to_owned(), result)
            })
            .collect()
    }

    fn this_computer() -> HashSet<[u8; 4]> {
        HashSet::from([[127, 0, 0, 1], [192, 168, 1, 10], [172, 20, 0, 1]])
    }

    #[test]
    fn names_are_resolved_to_their_addresses_and_addresses_taken_as_named() {
        let requests = requests(json!(["staging.mycompany.com:443", "192.168.1.50:8080", "10.1.2.3", "intranet.mycompany.com:443", "10.9.9.9:443"]));
        let resolved = found(&[
            ("staging.mycompany.com", Ok(vec![[93, 184, 216, 34], [93, 184, 216, 35], [93, 184, 216, 34]])),
            // A name leading to a private address that is also named itself.
            ("intranet.mycompany.com", Ok(vec![[10, 9, 9, 9]])),
        ]);
        let targets = resolve_targets(&requests, &resolved, &this_computer()).unwrap();
        let shown: Vec<(String, Vec<String>, Vec<u16>)> = targets
            .iter()
            .map(|target| (target.host.clone(), target.addresses.iter().map(ToString::to_string).collect(), target.ports.clone()))
            .collect();
        assert_eq!(
            shown,
            vec![
                ("staging.mycompany.com".into(), vec!["93.184.216.34".into(), "93.184.216.35".into()], vec![443]),
                ("192.168.1.50".into(), vec!["192.168.1.50".into()], vec![8080]),
                ("10.1.2.3".into(), vec!["10.1.2.3".into()], vec![]),
                ("intranet.mycompany.com".into(), vec!["10.9.9.9".into()], vec![443]),
                ("10.9.9.9".into(), vec!["10.9.9.9".into()], vec![443]),
            ]
        );
    }

    #[test]
    fn a_host_that_is_or_leads_to_this_computer_or_a_private_network_is_refused() {
        let check = |entries: Value, resolved: &[(&str, Result<Vec<[u8; 4]>, &str>)]| {
            resolve_targets(&requests(entries), &found(resolved), &this_computer()).unwrap_err()
        };
        let error = check(json!(["192.168.1.10:8080"]), &[]);
        assert!(error.contains("is an address of this computer"), "{error}");
        let error = check(json!(["172.20.0.1"]), &[]);
        assert!(error.contains("is an address of this computer"), "{error}");
        let error = check(json!(["mypc:8080"]), &[("mypc", Ok(vec![[192, 168, 1, 10]]))]);
        assert!(error.contains("leads to this computer (192.168.1.10)"), "{error}");
        let error = check(json!(["loop.example.com"]), &[("loop.example.com", Ok(vec![[127, 0, 0, 1]]))]);
        assert!(error.contains("leads to this computer"), "{error}");
        let error = check(json!(["meta.example.com"]), &[("meta.example.com", Ok(vec![[169, 254, 169, 254]]))]);
        assert!(error.contains("never reaches"), "{error}");
        let error = check(json!(["gw.example.com:80"]), &[("gw.example.com", Ok(vec![[10, 0, 2, 2]]))]);
        assert!(error.contains("never reaches"), "{error}");
        // A public name may not open the person's network by itself, nor reserved space that
        // labs and VPNs route (benchmarking, documentation).
        let error = check(json!(["rebind.example.com:443"]), &[("rebind.example.com", Ok(vec![[93, 184, 216, 34], [192, 168, 1, 50]]))]);
        assert!(error.contains("an address on a private network. Name 192.168.1.50:443 too"), "{error}");
        for reserved in [[198, 18, 0, 5], [198, 19, 1, 1], [192, 0, 2, 7], [198, 51, 100, 7], [203, 0, 113, 7], [192, 88, 99, 1]] {
            let error = check(json!(["lab.example.com:443"]), &[("lab.example.com", Ok(vec![reserved]))]);
            let shown = Ipv4Addr::from(reserved);
            assert!(error.contains(&format!("Name {shown}:443 too")), "{error}");
        }
        let named = resolve_targets(
            &requests(json!(["lab.example.com:443", "198.18.0.5:443"])),
            &found(&[("lab.example.com", Ok(vec![[198, 18, 0, 5]]))]),
            &this_computer(),
        )
        .unwrap();
        assert_eq!(named[0].addresses, vec![Ipv4Addr::new(198, 18, 0, 5)]);
        let error = check(json!(["missing.example.com"]), &[("missing.example.com", Err("No such host is known."))]);
        assert!(error.contains("could not be found from this computer"), "{error}");
        let error = check(json!(["v6only.example.com"]), &[("v6only.example.com", Ok(vec![]))]);
        assert!(error.contains("has no IPv4 address"), "{error}");
    }
}
