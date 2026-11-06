//! The host's sandbox address pool: host-assigned identities that are never host,
//! loopback, metadata or other-sandbox addresses, and disjoint NAT port blocks (VM-W59).

use super::*;
use crate::sandbox_contract::destinations::AddressClass;

fn refused(edit: impl FnOnce(&mut PoolConfig)) -> PoolError {
    let mut config = pool_config();
    edit(&mut config);
    SandboxAddressPool::new(config, &host_state()).unwrap_err()
}

#[test]
fn the_pool_is_private_space_holding_no_metadata_and_no_host_address_but_the_gateway() {
    assert!(matches!(
        refused(|config| config.ipv4 = prefix("151.101.0.0/24")),
        PoolError::Ipv4PoolNotPrivate {
            class: AddressClass::Public,
            ..
        }
    ));
    assert!(matches!(
        refused(|config| config.ipv4 = prefix("100.64.0.0/24")),
        PoolError::Ipv4PoolNotPrivate {
            class: AddressClass::SharedCgnat,
            ..
        }
    ));
    assert!(matches!(
        refused(|config| config.ipv6 = Some(prefix("2a04:4e42::/64"))),
        PoolError::Ipv6PoolNotUniqueLocal { .. }
    ));
    assert!(matches!(
        refused(|config| config.ipv6 = Some(prefix("fd00:ec2::/64"))),
        PoolError::PoolContainsMetadata { .. }
    ));
    assert!(matches!(
        refused(|config| config.ipv4 = prefix("10.0.0.0/8")),
        PoolError::PoolLength { .. }
    ));
    assert!(matches!(
        refused(|config| config.ipv4 = prefix("192.168.1.0/24")),
        PoolError::PoolOverlapsHost { .. }
    ));
    assert!(matches!(
        refused(|config| config.nat.egress_ipv6 = None),
        PoolError::Ipv6EgressMismatch
    ));
    assert!(matches!(
        refused(|config| config.nat.egress_ipv4 = "10.200.0.9".parse().unwrap()),
        PoolError::EgressInsidePool { .. }
    ));
    assert!(matches!(
        refused(|config| config.nat.egress_ipv4 = "127.0.0.1".parse().unwrap()),
        PoolError::EgressAddress {
            class: AddressClass::Loopback,
            ..
        }
    ));
    assert_eq!(
        refused(|config| config.socks_proxy_port = port(3128)),
        PoolError::ListenerPorts
    );
    assert_eq!(
        refused(|config| config.http_proxy_port = port(53)),
        PoolError::ListenerPorts
    );
    assert_eq!(
        refused(|config| config.nat.first_port = 80),
        PoolError::NatPortRange
    );
    assert_eq!(
        refused(|config| config.nat.first_port = 65_530),
        PoolError::NatPortRange
    );
    assert_eq!(
        refused(|config| config.nat.ports_per_sandbox = 0),
        PoolError::NatPortRange
    );
    // The gateway is host-owned and still allowed.
    assert!(host_state().owns(ip(GATEWAY)));
    assert!(SandboxAddressPool::new(pool_config(), &host_state()).is_ok());
}

#[test]
fn assignment_is_deterministic_lowest_free_and_skips_host_addresses() {
    let host = host_state();
    let mut first = new_pool();
    let mut second = new_pool();
    for label in ["sbx-a", "sbx-b", "sbx-c"] {
        assert_eq!(
            first.assign(exec(label), scope(label), &host).unwrap(),
            second.assign(exec(label), scope(label), &host).unwrap()
        );
    }
    assert_eq!(
        first.identity(&exec("sbx-a")).unwrap().ipv4.to_string(),
        "10.200.0.2"
    );
    assert_eq!(
        first
            .identity(&exec("sbx-a"))
            .unwrap()
            .ipv6
            .unwrap()
            .to_string(),
        "fd00:200::2"
    );
    assert_eq!(first.owner_of(ip("10.200.0.3")), Some(&exec("sbx-b")));
    assert_eq!(first.owner_of(ip("10.200.0.1")), None);

    first.release(&exec("sbx-b"));
    let reused = first.assign(exec("sbx-d"), scope("sbx-d"), &host).unwrap();
    assert_eq!(reused.ipv4.to_string(), "10.200.0.3");

    let later_host = HostAddressState::new(
        HostAddressGeneration::new(2),
        host.owned()
            .copied()
            .chain([IpPrefix::host(ip("10.200.0.5"))]),
    );
    let skipped = first
        .assign(exec("sbx-e"), scope("sbx-e"), &later_host)
        .unwrap();
    assert_eq!(skipped.ipv4.to_string(), "10.200.0.6");
    assert_eq!(
        first.assign(exec("sbx-a"), scope("sbx-a"), &host),
        Err(PoolError::AlreadyAssigned {
            execution: exec("sbx-a")
        })
    );
}

#[test]
fn only_vm_sandboxes_get_identities_and_a_full_pool_refuses() {
    let host = host_state();
    let mut pool = new_pool();
    assert_eq!(
        pool.assign(
            exec("gpu"),
            TrustScope::named(ExecutionCategory::SharedKernelGpuRuntime, "gpu"),
            &host
        ),
        Err(PoolError::NotVmSandbox)
    );
    let mut config = pool_config();
    config.ipv4 = prefix("10.200.0.0/29");
    let mut small = SandboxAddressPool::new(config, &host).unwrap();
    for index in 0..5 {
        let label = format!("s{index}");
        small.assign(exec(&label), scope(&label), &host).unwrap();
    }
    assert_eq!(
        small.assign(exec("s5"), scope("s5"), &host),
        Err(PoolError::AddressesExhausted)
    );
    let mut config = pool_config();
    config.nat.max_sandboxes = 1;
    let mut one_block = SandboxAddressPool::new(config, &host).unwrap();
    one_block.assign(exec("s0"), scope("s0"), &host).unwrap();
    assert_eq!(
        one_block.assign(exec("s1"), scope("s1"), &host),
        Err(PoolError::PortBlocksExhausted)
    );
}

#[test]
fn port_blocks_are_disjoint_and_inside_the_nat_range() {
    let host = host_state();
    let mut pool = new_pool();
    let mut blocks = Vec::new();
    for index in 0..16 {
        let label = format!("s{index}");
        pool.assign(exec(&label), scope(&label), &host).unwrap();
        blocks.push(pool.port_block(&exec(&label)).unwrap());
    }
    for (index, (first, size)) in blocks.iter().enumerate() {
        assert_eq!(*size, 8);
        assert!(*first >= 20_000);
        for (other_index, (other, _)) in blocks.iter().enumerate() {
            if index != other_index {
                assert!(first + size <= *other || other + size <= *first);
            }
        }
    }
    assert_eq!(pool.gateway_ipv4().unwrap().to_string(), GATEWAY);
    assert_eq!(pool.gateway_ipv6().unwrap().to_string(), GATEWAY_V6);
    assert_eq!(pool.egress_for(ip(PYPI_V6)), Some(ip(EGRESS_V6)));
}
