//! VM §4.2 step 4 and VM-P08: every address class, mapped and translated forms included.

use super::*;

fn class(text: &str) -> AddressClass {
    classify(ip(text), &host_state()).class
}

fn refused(text: &str) -> AddressRefused {
    AddressRule::ResolvedName
        .check(classify(ip(text), &host_state()))
        .unwrap_err()
}

#[test]
fn public_addresses_are_the_only_ones_a_resolved_name_may_use() {
    for public in [
        "8.8.8.8",
        "1.1.1.1",
        "93.184.216.34",
        "2001:4860:4860::8888",
        "2606:4700::1111",
    ] {
        assert_eq!(class(public), AddressClass::Public, "{public}");
        assert!(AddressRule::ResolvedName
            .check(classify(ip(public), &host_state()))
            .is_ok());
    }
}

#[test]
fn every_special_class_is_refused_for_a_resolved_name() {
    let cases: &[(&str, AddressClass)] = &[
        ("0.0.0.0", AddressClass::Unspecified),
        ("0.1.2.3", AddressClass::Unspecified),
        ("::", AddressClass::Unspecified),
        ("127.0.0.1", AddressClass::Loopback),
        ("127.255.0.9", AddressClass::Loopback),
        ("::1", AddressClass::Loopback),
        ("10.1.2.3", AddressClass::Private),
        ("172.16.0.1", AddressClass::Private),
        ("172.31.255.255", AddressClass::Private),
        ("192.168.7.7", AddressClass::Private),
        ("fd12:3456::1", AddressClass::Private),
        ("fc00::1", AddressClass::Private),
        ("100.64.0.1", AddressClass::SharedCgnat),
        ("100.127.255.254", AddressClass::SharedCgnat),
        ("169.254.1.1", AddressClass::LinkLocal),
        ("fe80::1", AddressClass::LinkLocal),
        ("169.254.169.254", AddressClass::Metadata),
        ("169.254.170.2", AddressClass::Metadata),
        ("168.63.129.16", AddressClass::Metadata),
        ("100.100.100.200", AddressClass::Metadata),
        ("fd00:ec2::254", AddressClass::Metadata),
        ("fd20:ce::254", AddressClass::Metadata),
        ("224.0.0.1", AddressClass::Multicast),
        ("239.255.255.250", AddressClass::Multicast),
        ("ff02::1", AddressClass::Multicast),
        ("255.255.255.255", AddressClass::Broadcast),
        ("192.0.2.1", AddressClass::Documentation),
        ("198.51.100.7", AddressClass::Documentation),
        ("203.0.113.9", AddressClass::Documentation),
        ("2001:db8::1", AddressClass::Documentation),
        ("3fff::1", AddressClass::Documentation),
        ("198.18.0.1", AddressClass::Benchmarking),
        ("198.19.255.1", AddressClass::Benchmarking),
        ("2001:2::1", AddressClass::Benchmarking),
        ("240.0.0.1", AddressClass::Reserved),
        ("192.0.0.8", AddressClass::Reserved),
        ("192.88.99.1", AddressClass::Reserved),
        ("100::1", AddressClass::Reserved),
        ("2001:10::1", AddressClass::Reserved),
        ("fec0::1", AddressClass::Reserved),
        ("4000::1", AddressClass::Reserved),
        ("192.168.1.10", AddressClass::HostOwned),
        ("100.101.102.103", AddressClass::HostOwned),
    ];
    for (address, expected) in cases {
        assert_eq!(class(address), *expected, "{address}");
        let refusal = refused(address);
        assert_eq!(refusal.verdict.class, *expected);
        assert_eq!(refusal.rule, AddressRule::ResolvedName);
    }
}

#[test]
fn mapped_and_translated_ipv6_forms_of_private_and_metadata_addresses_are_refused() {
    let cases: &[(&str, EmbeddedIpv4Form, &str, AddressClass)] = &[
        (
            "::ffff:10.0.0.1",
            EmbeddedIpv4Form::Mapped,
            "10.0.0.1",
            AddressClass::Private,
        ),
        (
            "::ffff:169.254.169.254",
            EmbeddedIpv4Form::Mapped,
            "169.254.169.254",
            AddressClass::Metadata,
        ),
        (
            "::ffff:127.0.0.1",
            EmbeddedIpv4Form::Mapped,
            "127.0.0.1",
            AddressClass::Loopback,
        ),
        (
            "::ffff:0:a9fe:a9fe",
            EmbeddedIpv4Form::Translated,
            "169.254.169.254",
            AddressClass::Metadata,
        ),
        (
            "::ffff:0:c0a8:101",
            EmbeddedIpv4Form::Translated,
            "192.168.1.1",
            AddressClass::Private,
        ),
        (
            "64:ff9b::a9fe:a9fe",
            EmbeddedIpv4Form::Nat64WellKnown,
            "169.254.169.254",
            AddressClass::Metadata,
        ),
        (
            "64:ff9b::a00:1",
            EmbeddedIpv4Form::Nat64WellKnown,
            "10.0.0.1",
            AddressClass::Private,
        ),
        // RFC 6052 /48 layout: 169.254 in bits 48-63, 169.254 again after the zero octet.
        (
            "64:ff9b:1:a9fe:a9:fe00::",
            EmbeddedIpv4Form::Nat64LocalUse,
            "169.254.169.254",
            AddressClass::Metadata,
        ),
        (
            "2002:a9fe:a9fe::1",
            EmbeddedIpv4Form::SixToFour,
            "169.254.169.254",
            AddressClass::Metadata,
        ),
        (
            "2002:c0a8:10a::1",
            EmbeddedIpv4Form::SixToFour,
            "192.168.1.10",
            AddressClass::HostOwned,
        ),
        // Teredo stores the client address inverted: !10.0.0.1 = f5ff:fffe.
        (
            "2001:0:4136:e378:8000:63bf:f5ff:fffe",
            EmbeddedIpv4Form::Teredo,
            "10.0.0.1",
            AddressClass::Private,
        ),
        (
            "::10.0.0.1",
            EmbeddedIpv4Form::Compatible,
            "10.0.0.1",
            AddressClass::Private,
        ),
    ];
    for (address, form, ipv4, ipv4_class) in cases {
        let verdict = classify(ip(address), &host_state());
        assert_eq!(
            verdict.class,
            AddressClass::EmbeddedIpv4(*form),
            "{address}"
        );
        let embedded = verdict.embedded.unwrap();
        assert_eq!(IpAddr::V4(embedded.ipv4), ip(ipv4), "{address}");
        assert_eq!(embedded.ipv4_class, *ipv4_class, "{address}");
        assert!(AddressRule::ResolvedName.check(verdict).is_err());
        assert!(AddressRule::ExactEndpoint.check(verdict).is_err());
    }
    // Even a public address is refused in a mapped form: it must be presented as IPv4.
    let mapped_public = classify(ip("::ffff:8.8.8.8"), &host_state());
    assert_eq!(
        mapped_public.embedded.unwrap().ipv4_class,
        AddressClass::Public
    );
    assert!(AddressRule::ResolvedName.check(mapped_public).is_err());
    let message = AddressRule::ResolvedName
        .check(classify(ip("::ffff:169.254.169.254"), &host_state()))
        .unwrap_err()
        .to_string();
    assert!(message.contains("169.254.169.254"), "{message}");
}

#[test]
fn an_exact_endpoint_may_be_private_or_cgnat_but_never_loopback_metadata_or_host_owned() {
    for allowed in ["10.0.5.20", "fd12::20", "100.64.3.3", "8.8.8.8"] {
        assert!(
            AddressRule::ExactEndpoint
                .check(classify(ip(allowed), &host_state()))
                .is_ok(),
            "{allowed}"
        );
    }
    for forbidden in [
        "127.0.0.1",
        "169.254.169.254",
        "169.254.3.3",
        "192.168.1.10",
        "224.0.0.9",
        "0.0.0.0",
        "192.0.2.5",
        "::ffff:10.0.5.20",
        "fe80::2",
    ] {
        assert!(
            AddressRule::ExactEndpoint
                .check(classify(ip(forbidden), &host_state()))
                .is_err(),
            "{forbidden}"
        );
    }
}

#[test]
fn host_owned_addresses_come_from_the_host_state_and_win_over_other_classes() {
    let empty = HostAddressState::new(HostAddressGeneration::FIRST, []);
    assert_eq!(
        classify(ip("93.184.216.34"), &empty).class,
        AddressClass::Public
    );
    let owning = HostAddressState::new(
        HostAddressGeneration::new(2),
        [IpPrefix::host(ip("93.184.216.34"))],
    );
    assert_eq!(
        classify(ip("93.184.216.34"), &owning).class,
        AddressClass::HostOwned
    );
    let prefix = HostAddressState::new(
        HostAddressGeneration::new(3),
        [IpPrefix::new(ip("203.0.113.0"), 24).unwrap()],
    );
    assert_eq!(
        classify(ip("203.0.113.77"), &prefix).class,
        AddressClass::HostOwned
    );
}

#[test]
fn prefixes_refuse_host_bits_and_overlong_lengths() {
    assert_eq!(
        IpPrefix::new(ip("10.0.0.1"), 8),
        Err(PrefixError::HostBitsSet)
    );
    assert_eq!(
        IpPrefix::new(ip("10.0.0.0"), 33),
        Err(PrefixError::LengthTooLong {
            length: 33,
            max: 32
        })
    );
    assert_eq!(
        IpPrefix::new(ip("fd00::"), 129),
        Err(PrefixError::LengthTooLong {
            length: 129,
            max: 128
        })
    );
    let cgnat = IpPrefix::new(ip("100.64.0.0"), 10).unwrap();
    assert!(cgnat.contains(ip("100.127.0.1")));
    assert!(!cgnat.contains(ip("100.128.0.1")));
    assert!(!cgnat.contains(ip("::ffff:100.64.0.1")));
    assert!(cgnat.overlaps(&IpPrefix::new(ip("100.64.0.0"), 16).unwrap()));
    assert!(!cgnat.overlaps(&IpPrefix::new(ip("198.18.0.0"), 15).unwrap()));
    let all = IpPrefix::new(ip("0.0.0.0"), 0).unwrap();
    assert!(all.contains(ip("8.8.8.8")));
    assert!(IpPrefix::new(ip("fd00:ec2::"), 32)
        .unwrap()
        .contains(ip("fd00:ec2::254")));
    let round_trip: IpPrefix =
        serde_json::from_str(&serde_json::to_string(&cgnat).unwrap()).unwrap();
    assert_eq!(round_trip, cgnat);
    assert!(serde_json::from_str::<IpPrefix>(r#"{"network":"10.0.0.1","length":8}"#).is_err());
    assert!(
        serde_json::from_str::<IpPrefix>(r#"{"network":"10.0.0.0","length":8,"x":1}"#).is_err()
    );
}
