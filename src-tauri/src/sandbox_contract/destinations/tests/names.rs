//! VM §4.2 steps 1–2: one parser for names, ports and authorities.

use super::super::punycode;
use super::*;

fn name_error(text: &str) -> NameError {
    CanonicalName::parse(text).unwrap_err()
}

fn authority_error(text: &str) -> NameError {
    Authority::parse(text, DestinationPort::HTTPS).unwrap_err()
}

fn literal(form: IpLiteralForm) -> NameError {
    NameError::IpLiteral { form }
}

#[test]
fn good_names_canonicalize_to_one_lowercase_form() {
    assert_eq!(name("API.Example.COM").as_str(), "api.example.com");
    assert_eq!(name("api.example.com"), name("Api.Example.Com"));
    assert_eq!(name("a-b.example.co.uk").label_count(), 4);
    assert_eq!(name("1e100.net").as_str(), "1e100.net");
    assert_eq!(name("123.example.com").as_str(), "123.example.com");
    // A valid A-label is accepted; its case folds like any ASCII.
    assert_eq!(
        name("XN--BCHER-KVA.example.com").as_str(),
        "xn--bcher-kva.example.com"
    );
    let longest_label = "a".repeat(MAX_LABEL_BYTES);
    assert!(CanonicalName::parse(&format!("{longest_label}.com")).is_ok());
    // 63 + 1 + 63 + 1 + 63 + 1 + 61 = 253 bytes.
    let longest = format!("{0}.{0}.{0}.{1}", "a".repeat(63), "b".repeat(61));
    assert_eq!(longest.len(), MAX_NAME_BYTES);
    assert!(CanonicalName::parse(&longest).is_ok());
}

#[test]
fn authorities_canonicalize_host_and_port_under_the_same_parser() {
    let default = Authority::parse("API.example.com", DestinationPort::HTTPS).unwrap();
    let explicit = Authority::parse("api.example.com:443", DestinationPort::HTTPS).unwrap();
    assert_eq!(default, explicit);
    assert_eq!(default.to_string(), "api.example.com:443");
    assert_eq!(
        Authority::parse("api.example.com:8443", DestinationPort::HTTPS)
            .unwrap()
            .port,
        port(8443)
    );
    assert_eq!(
        Authority::parse("8.8.8.8:53", DestinationPort::HTTPS)
            .unwrap()
            .host,
        DestinationHost::Address(ip("8.8.8.8"))
    );
    let v6 = Authority::parse("[2001:4860:4860::8888]", DestinationPort::HTTPS).unwrap();
    assert_eq!(
        v6.host,
        DestinationHost::Address(ip("2001:4860:4860::8888"))
    );
    assert_eq!(v6.to_string(), "[2001:4860:4860::8888]:443");
}

#[test]
fn malformed_names_are_refused() {
    assert_eq!(name_error(""), NameError::Empty);
    assert_eq!(name_error("a..example.com"), NameError::EmptyLabel);
    assert_eq!(name_error(".example.com"), NameError::EmptyLabel);
    assert_eq!(
        name_error("-a.example.com"),
        NameError::HyphenAtLabelEdge {
            label: "-a".to_owned()
        }
    );
    assert_eq!(
        name_error("a-.example.com"),
        NameError::HyphenAtLabelEdge {
            label: "a-".to_owned()
        }
    );
    assert_eq!(
        name_error("ab--cd.example.com"),
        NameError::ReservedHyphenLabel {
            label: "ab--cd".to_owned()
        }
    );
    assert_eq!(
        name_error("under_score.example.com"),
        NameError::InvalidCharacter { character: '_' }
    );
    assert_eq!(
        name_error("exa mple.com"),
        NameError::InvalidCharacter { character: ' ' }
    );
    assert_eq!(
        name_error("example.com\0.evil.com"),
        NameError::InvalidCharacter { character: '\0' }
    );
    assert_eq!(
        name_error("a\\b.example.com"),
        NameError::InvalidCharacter { character: '\\' }
    );
    assert_eq!(
        name_error(&format!("{}.com", "a".repeat(64))),
        NameError::LabelTooLong { bytes: 64 }
    );
    let too_long = format!("{0}.{0}.{0}.{1}", "a".repeat(63), "b".repeat(62));
    assert_eq!(name_error(&too_long), NameError::TooLong { bytes: 254 });
}

#[test]
fn single_labels_are_refused_so_no_search_suffix_can_complete_them() {
    for single in ["localhost", "db", "metadata", "intranet"] {
        assert_eq!(name_error(single), NameError::SingleLabel, "{single}");
    }
}

#[test]
fn trailing_dots_are_refused_rather_than_stripped() {
    assert_eq!(name_error("example.com."), NameError::TrailingDot);
    assert_eq!(authority_error("example.com.:443"), NameError::TrailingDot);
    assert_eq!(authority_error("example.com."), NameError::TrailingDot);
}

#[test]
fn non_ascii_and_encoded_names_are_refused() {
    assert_eq!(name_error("bücher.example.com"), NameError::NonAscii);
    // A full-width ideographic full stop would act as a dot after IDNA mapping.
    assert_eq!(name_error("example\u{3002}com"), NameError::NonAscii);
    assert_eq!(name_error("ex%61mple.com"), NameError::AmbiguousEncoding);
    assert_eq!(
        authority_error("ex%61mple.com"),
        NameError::AmbiguousEncoding
    );
    assert_eq!(authority_error("bücher.example.com"), NameError::NonAscii);
}

#[test]
fn userinfo_is_refused() {
    assert_eq!(authority_error("user@example.com"), NameError::Userinfo);
    assert_eq!(
        authority_error("user:pass@example.com:443"),
        NameError::Userinfo
    );
    assert_eq!(
        authority_error("api.example.com@evil.example.net"),
        NameError::Userinfo
    );
    assert_eq!(name_error("user@example.com"), NameError::Userinfo);
}

#[test]
fn every_ipv4_literal_spelling_other_than_the_dotted_quad_is_refused() {
    assert_eq!(authority_error("127.1"), literal(IpLiteralForm::ShortIpv4));
    assert_eq!(authority_error("10.1.1"), literal(IpLiteralForm::ShortIpv4));
    assert_eq!(
        authority_error("0177.0.0.1"),
        literal(IpLiteralForm::OctalIpv4)
    );
    assert_eq!(
        authority_error("010.0.0.1"),
        literal(IpLiteralForm::OctalIpv4)
    );
    assert_eq!(
        authority_error("0x7f.0.0.1"),
        literal(IpLiteralForm::HexIpv4)
    );
    assert_eq!(
        authority_error("0x7f000001"),
        literal(IpLiteralForm::HexIpv4)
    );
    assert_eq!(authority_error("0X7F.1"), literal(IpLiteralForm::HexIpv4));
    assert_eq!(
        authority_error("2130706433"),
        literal(IpLiteralForm::DecimalIntegerIpv4)
    );
    assert_eq!(
        authority_error("256.1.1.1"),
        literal(IpLiteralForm::MalformedIpv4)
    );
    assert_eq!(
        authority_error("1.2.3.4.5"),
        literal(IpLiteralForm::MalformedIpv4)
    );
    assert_eq!(
        authority_error("example.123"),
        literal(IpLiteralForm::NumericFinalLabel)
    );
    assert_eq!(
        authority_error("evil.0x10"),
        literal(IpLiteralForm::NumericFinalLabel)
    );
    // In a name position even the canonical dotted quad is refused.
    assert_eq!(
        name_error("1.2.3.4"),
        literal(IpLiteralForm::DottedQuadAsName)
    );
    assert_eq!(
        name_error("2130706433"),
        literal(IpLiteralForm::DecimalIntegerIpv4)
    );
    assert_eq!(name_error("127.1"), literal(IpLiteralForm::ShortIpv4));
}

#[test]
fn ipv6_literals_must_be_bracketed_canonical_and_zone_free() {
    assert_eq!(
        authority_error("::1"),
        literal(IpLiteralForm::UnbracketedIpv6)
    );
    assert_eq!(
        authority_error("fe80::1:443"),
        literal(IpLiteralForm::UnbracketedIpv6)
    );
    assert_eq!(
        authority_error("[0:0::1]"),
        literal(IpLiteralForm::NonCanonicalIpv6)
    );
    assert_eq!(
        authority_error("[::FFFF:7F00:1]"),
        literal(IpLiteralForm::NonCanonicalIpv6)
    );
    assert_eq!(
        authority_error("[2001:db8:0:0:0:0:0:1]"),
        literal(IpLiteralForm::NonCanonicalIpv6)
    );
    assert_eq!(
        authority_error("[fe80::1%25eth0]"),
        literal(IpLiteralForm::Ipv6ZoneId)
    );
    assert_eq!(
        authority_error("[fe80::1%eth0]"),
        literal(IpLiteralForm::Ipv6ZoneId)
    );
    assert_eq!(
        authority_error("[not-an-address]"),
        literal(IpLiteralForm::NonCanonicalIpv6)
    );
    assert_eq!(
        authority_error("[::1"),
        NameError::InvalidCharacter { character: '[' }
    );
    assert_eq!(
        authority_error("[::1]x"),
        NameError::InvalidCharacter { character: 'x' }
    );
    assert_eq!(
        name_error("::1"),
        NameError::InvalidCharacter { character: ':' }
    );
}

#[test]
fn ports_are_decimal_without_sign_or_leading_zeros() {
    for bad in [
        "example.com:",
        "example.com:0443",
        "example.com:0",
        "example.com:65536",
        "example.com:+443",
        "example.com:44 3",
        "example.com:https",
    ] {
        assert!(
            matches!(
                authority_error(bad),
                NameError::InvalidPort { .. }
                    | NameError::IpLiteral { .. }
                    | NameError::InvalidCharacter { .. }
            ),
            "{bad}"
        );
    }
    assert_eq!(
        authority_error("example.com:0443"),
        NameError::InvalidPort {
            text: "0443".to_owned()
        }
    );
    assert_eq!(
        DestinationPort::new(0),
        Err(NameError::InvalidPort {
            text: "0".to_owned()
        })
    );
    assert_eq!(DestinationPort::parse("65535").unwrap().get(), 65535);
    assert!(serde_json::from_str::<DestinationPort>("0").is_err());
}

#[test]
fn a_labels_must_decode_canonically_to_a_plausible_u_label() {
    let undecodable = name_error("xn--9999999999.example.com");
    assert!(matches!(
        undecodable,
        NameError::InvalidALabel {
            problem: ALabelProblem::Undecodable,
            ..
        }
    ));
    // A leading delimiter with no basic code points is a second spelling of "xn--kva".
    assert!(matches!(
        name_error("xn---kva.example.com"),
        NameError::InvalidALabel {
            problem: ALabelProblem::NotCanonical | ALabelProblem::DisallowedCodePoint,
            ..
        }
    ));
    let uppercase = punycode::encode(&[0xdc]).unwrap();
    assert!(matches!(
        name_error(&format!("xn--{uppercase}.example.com")),
        NameError::InvalidALabel {
            problem: ALabelProblem::DisallowedCodePoint,
            ..
        }
    ));
    let zero_width: Vec<u32> = "a\u{200d}b".chars().map(u32::from).collect();
    let encoded = punycode::encode(&zero_width).unwrap();
    assert!(matches!(
        name_error(&format!("xn--{encoded}.example.com")),
        NameError::InvalidALabel {
            problem: ALabelProblem::DisallowedCodePoint,
            ..
        }
    ));
    let dot_like: Vec<u32> = "a\u{ff0e}b".chars().map(u32::from).collect();
    let encoded = punycode::encode(&dot_like).unwrap();
    assert!(matches!(
        name_error(&format!("xn--{encoded}.example.com")),
        NameError::InvalidALabel {
            problem: ALabelProblem::DisallowedCodePoint,
            ..
        }
    ));
}

#[test]
fn wire_length_and_suffix_relations_follow_dns() {
    // 1+3 + 1+7 + 1+3 + 1 root byte.
    assert_eq!(name("api.example.com").wire_length_bytes(), 17);
    assert!(name("a.example.com").is_below(&name("example.com")));
    assert!(name("a.example.com").is_one_label_below(&name("example.com")));
    assert!(!name("a.b.example.com").is_one_label_below(&name("example.com")));
    assert!(!name("badexample.com").is_below(&name("example.com")));
    assert!(!name("example.com").is_below(&name("example.com")));
}

#[test]
fn special_use_suffixes_are_recognized() {
    assert_eq!(name("db.internal").special_use_suffix(), Some("internal"));
    assert_eq!(
        name("metadata.google.internal").special_use_suffix(),
        Some("internal")
    );
    assert_eq!(name("printer.local").special_use_suffix(), Some("local"));
    assert_eq!(
        name("app.localhost").special_use_suffix(),
        Some("localhost")
    );
    assert_eq!(
        name("router.home.arpa").special_use_suffix(),
        Some("home.arpa")
    );
    assert_eq!(
        name("metadata.goog").special_use_suffix(),
        Some("metadata.goog")
    );
    assert_eq!(name("api.example.com").special_use_suffix(), None);
    assert_eq!(name("notlocal.com").special_use_suffix(), None);
}

#[test]
fn stored_names_must_already_be_canonical() {
    let stored: CanonicalName = serde_json::from_str("\"api.example.com\"").unwrap();
    assert_eq!(stored, name("api.example.com"));
    assert!(serde_json::from_str::<CanonicalName>("\"API.example.com\"").is_err());
    assert!(serde_json::from_str::<CanonicalName>("\"example.com.\"").is_err());
    assert_eq!(
        serde_json::to_string(&stored).unwrap(),
        "\"api.example.com\""
    );
}

#[test]
fn equivalent_spellings_of_a_destination_have_one_route_reference() {
    let reference =
        |text: &str| route_reference(&Authority::parse(text, DestinationPort::HTTPS).unwrap());
    for spelling in [
        "registry.example.com",
        "REGISTRY.Example.com",
        "registry.example.com:443",
        "Registry.EXAMPLE.COM:443",
    ] {
        assert_eq!(reference(spelling), "registry.example.com:443");
    }
    assert_eq!(
        reference("registry.example.com:8443"),
        "registry.example.com:8443"
    );
    assert_eq!(reference("10.0.0.1"), "10.0.0.1:443");
    assert_eq!(reference("[2001:db8::1]:8443"), "[2001:db8::1]:8443");
    // The reference is the authority's canonical text, so a module that already names a
    // route by `authority.to_string()` names it identically.
    for text in ["api.example.com:8443", "10.0.0.1", "[2001:db8::1]"] {
        let authority = Authority::parse(text, DestinationPort::HTTPS).unwrap();
        assert_eq!(route_reference(&authority), authority.to_string());
    }
}
