//! The guard end to end against a real V11 `HostNetwork`: V11's decision put on the wire,
//! its bindings admitting the flows that follow, TTLs from the host clock.

use super::*;
use crate::sandbox_contract::destinations::{
    AuthorizationRefusal, DestinationRefusal, NameError, ReleaseError, ResolverAnswer,
    ResolverFailure,
};
use crate::sandbox_contract::netprofile::{DnsAnswer, FlowKind, ProfileError};

const V4: AddressFamily = AddressFamily::Ipv4;
const V6: AddressFamily = AddressFamily::Ipv6;

/// The decoded response, checked to keep the query's id and to agree with the reply.
fn response(reply: &GuardReply, message: &[u8]) -> Decoded {
    let decoded = decode(reply.response.as_ref().unwrap());
    assert_eq!(decoded.id, u16::from_be_bytes([message[0], message[1]]));
    assert_eq!(Some(decoded.code), reply.code);
    decoded
}

/// V11's answer behind a reply.
fn decided(reply: &GuardReply) -> &DnsAnswer {
    match &reply.outcome {
        GuardOutcome::Decided { answer, .. } => answer,
        other => panic!("expected a V11 decision, got {other:?}"),
    }
}

fn sent(reply: &GuardReply) -> (Vec<IpAddr>, u32) {
    match &reply.outcome {
        GuardOutcome::Decided {
            sent, ttl_seconds, ..
        } => (sent.clone(), *ttl_seconds),
        other => panic!("expected a V11 decision, got {other:?}"),
    }
}

fn refused_with(reply: &GuardReply) -> &FlowRefusal {
    match decided(reply) {
        DnsAnswer::Refused(refusal) => refusal,
        other => panic!("expected a V11 refusal, got {other:?}"),
    }
}

#[test]
fn a_granted_name_is_answered_with_v11s_validated_addresses() {
    let clock = clock();
    let mut world = World::new(&clock);
    let a = world.add("sbx-a", |_| {});
    let message = query(0x1234, "pypi.org", TYPE_A);
    let reply = world.ask(&a, &message);

    let decoded = response(&reply, &message);
    assert_eq!(decoded.code, ResponseCode::NoError);
    assert_eq!(decoded.question, question_bytes(&message));
    assert_eq!(
        decoded.answers,
        vec![(ip(PYPI_V4), 120), (ip(PYPI_V4_B), 120)]
    );
    assert!(matches!(
        decided(&reply),
        DnsAnswer::Addresses { route: answered, external: true, .. } if *answered == route("pypi")
    ));
    assert_eq!(sent(&reply), (vec![ip(PYPI_V4), ip(PYPI_V4_B)], 120));
    // Only the grant's own resolver was asked, for the canonical name; the query was
    // charged: one name-budget unit and 12 + 10 + 4 released DNS bytes.
    assert_eq!(world.dns.queried_names(), vec!["pypi.org".to_owned()]);
    assert_eq!(world.rogue.calls(), 0);
    assert_eq!(world.net.usage(&a, &route("pypi")).dns_queries, 1);
    assert_eq!(world.dns_released(&a), 26);
}

#[test]
fn the_question_is_echoed_exactly_and_only_the_canonical_name_reaches_the_resolver() {
    let clock = clock();
    let mut world = World::new(&clock);
    let a = world.add("sbx-a", |_| {});
    // Case randomization (DNS 0x20) and the transaction id stay with the guard.
    let message = query(0xBEEF, "pYpI.OrG", TYPE_A);
    let reply = world.ask(&a, &message);
    let decoded = response(&reply, &message);
    assert_eq!(decoded.question, question_bytes(&message));
    assert_eq!(decoded.answers.len(), 2);
    assert_eq!(world.dns.queried_names(), vec!["pypi.org".to_owned()]);
}

#[test]
fn an_answer_creates_the_binding_a_following_flow_is_admitted_against() {
    let clock = clock();
    let mut world = World::new(&clock);
    let a = world.add("sbx-a", |_| {});
    // Before any answer, the address is not reachable.
    assert!(matches!(
        world.tcp(&a, PYPI_V4, 443),
        Err(FlowRefusal::Authorization(
            AuthorizationRefusal::AddressNeedsEndpointGrant { .. }
        ))
    ));
    let reply = world.ask(&a, &query(1, "pypi.org", TYPE_A));
    assert_eq!(reply.code, Some(ResponseCode::NoError));
    let admitted = world.tcp(&a, PYPI_V4, 443).unwrap();
    assert_eq!(
        admitted.kind,
        FlowKind::Named {
            route: route("pypi"),
            name: name("pypi.org"),
        }
    );
    // The same holds for IPv6 from the sandbox's IPv6 address.
    let reply = world.ask(&a, &query(2, "pypi.org", TYPE_AAAA));
    assert_eq!(sent(&reply).0, vec![ip(PYPI_V6)]);
    assert!(world.tcp(&a, PYPI_V6, 443).is_ok());
}

#[test]
fn the_ttl_comes_from_the_host_clock_and_never_outlasts_the_binding() {
    // The reviewer's skew case: the guard once read a clock of its own, 500 s behind the
    // broker's, and sent a TTL longer than the answer. The host clock here has moved 500 s
    // since admission; the TTL is still what remains of the answer, and the guest's cached
    // answer ends exactly when V11's binding does.
    let clock = clock();
    let mut world = World::new(&clock);
    let a = world.add("sbx-a", |_| {});
    clock.advance(Duration::from_secs(500));
    let reply = world.ask(&a, &query(1, "github.com", TYPE_A));
    let (addresses, ttl) = sent(&reply);
    assert_eq!(addresses, vec![ip(GITHUB_V4)]);
    assert_eq!(ttl, 60);
    let DnsAnswer::Addresses { valid_until, .. } = decided(&reply) else {
        panic!("addresses expected");
    };
    let remaining = valid_until.saturating_duration_since(world.net.now());
    assert!(Duration::from_secs(u64::from(ttl)) <= remaining);
    clock.advance(Duration::from_secs(u64::from(ttl) - 1));
    assert!(world.tcp(&a, GITHUB_V4, 443).is_ok());
    clock.advance(Duration::from_secs(1));
    assert_eq!(
        world.tcp(&a, GITHUB_V4, 443),
        Err(FlowRefusal::BindingExpired {
            address: ip(GITHUB_V4)
        })
    );

    // A long upstream TTL is capped at the profile's longest answer lifetime.
    world.dns.answer("github.com", V4, &[GITHUB_V4], 86_400);
    let reply = world.ask(&a, &query(2, "github.com", TYPE_A));
    assert_eq!(sent(&reply).1, 300);

    // An answer whose lifetime is already over is not sent.
    world.dns.answer("github.com", V4, &[GITHUB_V4], 0);
    let message = query(3, "github.com", TYPE_A);
    let reply = world.ask(&a, &message);
    let decoded = response(&reply, &message);
    assert_eq!(decoded.code, ResponseCode::ServFail);
    assert!(decoded.answers.is_empty());
    assert!(matches!(reply.outcome, GuardOutcome::Expired { .. }));
}

#[test]
fn an_ungranted_name_is_nonexistent_without_any_external_query() {
    let clock = clock();
    let mut world = World::new(&clock);
    let a = world.add("sbx-a", |_| {});
    let first = query(0x0101, "evil.example.com", TYPE_A);
    let second = query(0x0202, "files.pythonhosted.org", TYPE_AAAA);
    let first_reply = world.ask(&a, &first);
    let second_reply = world.ask(&a, &second);
    for (reply, message) in [(&first_reply, &first), (&second_reply, &second)] {
        let decoded = response(reply, message);
        assert_eq!(decoded.code, ResponseCode::NxDomain);
        assert_eq!(decoded.question, question_bytes(message));
        assert!(decoded.answers.is_empty());
        assert_eq!(decided(reply), &DnsAnswer::NameNotAuthorized);
    }
    // The fixed shape: the same flags and counts whatever the name.
    assert_eq!(
        first_reply.response.as_ref().unwrap()[2..12],
        second_reply.response.as_ref().unwrap()[2..12]
    );
    assert_eq!(world.external_calls(), 0);
    assert_eq!(world.dns_released(&a), 0);
}

#[test]
fn search_suffix_trailing_dot_idn_and_literal_spellings_follow_v11() {
    let clock = clock();
    let mut world = World::new(&clock);
    let a = world.add("sbx-a", |document| {
        document
            .egress
            .push(name_grant("books", "xn--bcher-kva.example.com", &[], false));
    });
    world
        .dns
        .answer("xn--bcher-kva.example.com", V4, &["93.184.216.34"], 60);

    // Malformed under V02's parser, decided by V11: a single label a resolver would
    // complete with search suffixes, IP-literal spellings, an undecodable A-label, an
    // underscore and the root name.
    let malformed: [&[&[u8]]; 7] = [
        &[b"pypi"],
        &[b"127", b"1"],
        &[b"151", b"101", b"0", b"223"],
        &[b"xn--9999999999", b"example", b"com"],
        &[b"xn---kva", b"example", b"com"],
        &[b"_dmarc", b"pypi", b"org"],
        &[],
    ];
    for labels in malformed {
        let message = query_labels(1, labels, TYPE_A, CLASS_IN);
        let reply = world.ask(&a, &message);
        assert_eq!(response(&reply, &message).code, ResponseCode::NxDomain);
        assert!(
            matches!(decided(&reply), DnsAnswer::Malformed(_)),
            "{labels:?}"
        );
    }
    // A guest search suffix appended to a granted name is another, ungranted name.
    let suffixed = query(2, "pypi.org.corp.lan", TYPE_A);
    let reply = world.ask(&a, &suffixed);
    assert_eq!(decided(&reply), &DnsAnswer::NameNotAuthorized);

    // Wire labels with a dot inside, which joined would read as `pypi.org` or
    // `pypi.org.`, and raw UTF-8: no text form without a guess, so V11 is not asked.
    let unwritable: [(&[&[u8]], NameError); 3] = [
        (
            &[b"pypi.org"],
            NameError::InvalidCharacter { character: '.' },
        ),
        (
            &[b"pypi", b"org."],
            NameError::InvalidCharacter { character: '.' },
        ),
        (
            &["bücher".as_bytes(), b"example", b"com"],
            NameError::NonAscii,
        ),
    ];
    for (labels, error) in unwritable {
        let message = query_labels(3, labels, TYPE_A, CLASS_IN);
        let reply = world.ask(&a, &message);
        assert_eq!(response(&reply, &message).code, ResponseCode::NxDomain);
        assert_eq!(reply.outcome, GuardOutcome::UnwritableName(error));
    }
    assert_eq!(world.external_calls(), 0);

    // The A-label in any ASCII case is the granted name.
    let a_label = query(4, "XN--BCHER-KVA.Example.com", TYPE_A);
    let reply = world.ask(&a, &a_label);
    assert_eq!(
        response(&reply, &a_label).answers,
        vec![(ip("93.184.216.34"), 60)]
    );
    assert_eq!(
        world.dns.queried_names(),
        vec!["xn--bcher-kva.example.com".to_owned()]
    );
}

#[test]
fn aaaa_without_an_ipv6_grant_or_identity_is_nodata_without_a_query() {
    let clock = clock();
    let mut world = World::new(&clock);
    let a = world.add("sbx-a", |_| {});
    // github.com has no IPv6 grant.
    let message = query(1, "github.com", TYPE_AAAA);
    let reply = world.ask(&a, &message);
    let decoded = response(&reply, &message);
    assert_eq!(decoded.code, ResponseCode::NoError);
    assert!(decoded.answers.is_empty());
    assert_eq!(decided(&reply), &DnsAnswer::NoData);
    assert_eq!(world.external_calls(), 0);

    // A sandbox without an IPv6 address: NODATA for every name, nothing resolved or
    // charged.
    let clock = super::clock();
    let mut world = World::with_pool(&clock, pool(false));
    let b = world.add("sbx-b", |_| {});
    let message = query(2, "pypi.org", TYPE_AAAA);
    let reply = world.ask(&b, &message);
    assert_eq!(response(&reply, &message).code, ResponseCode::NoError);
    assert_eq!(decided(&reply), &DnsAnswer::NoData);
    assert_eq!(world.external_calls(), 0);
    assert_eq!(world.net.usage(&b, &route("pypi")).dns_queries, 0);
}

#[test]
fn the_reviewers_two_route_cases_now_answer_correctly() {
    let clock = clock();
    let mut world = World::new(&clock);
    // One name on two routes cannot be declared, so the guard never has to choose.
    let two_ports = world.try_add("sbx-a", |document| {
        document.egress.push(EgressGrant {
            id: route("pypi-alt"),
            port: port(8443),
            ..name_grant("pypi-alt", "pypi.org", &["151.101.0.0/24"], false)
        });
    });
    assert!(matches!(
        two_ports,
        Err(AdmitError::Profile(
            ProfileError::NameInSeveralGrants { .. }
        ))
    ));
    let mut world = World::new(&clock);
    let named_twice = world.try_add("sbx-a", |document| {
        document.egress.push(endpoint_grant(
            "pypi-private",
            REGISTRY,
            5000,
            Some("pypi.org"),
        ));
    });
    assert!(matches!(
        named_twice,
        Err(AdmitError::Profile(
            ProfileError::NameInSeveralGrants { .. }
        ))
    ));

    // IPv6 granted on 8443 only: AAAA is answered, whatever the port.
    let mut world = World::new(&clock);
    let a = world.add("sbx-a", |document| {
        for grant in &mut document.egress {
            if grant.id == route("pypi") {
                grant.port = port(8443);
            }
        }
    });
    let message = query(1, "pypi.org", TYPE_AAAA);
    let reply = world.ask(&a, &message);
    assert_eq!(response(&reply, &message).answers, vec![(ip(PYPI_V6), 120)]);
    assert!(world.tcp(&a, PYPI_V6, 8443).is_ok());

    // A named endpoint: its fixed address, answered locally, nothing resolved.
    let message = query(2, "Registry.Corp.Internal", TYPE_A);
    let reply = world.ask(&a, &message);
    assert_eq!(
        response(&reply, &message).answers,
        vec![(ip(REGISTRY), 300)]
    );
    assert!(matches!(
        decided(&reply),
        DnsAnswer::Addresses {
            external: false,
            ..
        }
    ));
    let aaaa = query(3, "registry.corp.internal", TYPE_AAAA);
    let reply = world.ask(&a, &aaaa);
    assert_eq!(decided(&reply), &DnsAnswer::NoData);
    assert_eq!(world.dns.calls(), 1);
    assert_eq!(world.net.usage(&a, &route("registry")).dns_queries, 0);
}

#[test]
fn other_types_are_not_implemented_by_v11_and_other_classes_by_the_parser() {
    let clock = clock();
    let mut world = World::new(&clock);
    let a = world.add("sbx-a", |_| {});
    for qtype in [5u16, 12, 15, 16, 33, 64, 65, 255] {
        let message = query(6, "pypi.org", qtype);
        let reply = world.ask(&a, &message);
        let decoded = response(&reply, &message);
        assert_eq!(decoded.code, ResponseCode::NotImp);
        assert_eq!(decoded.question, question_bytes(&message));
        assert!(matches!(decided(&reply), DnsAnswer::Unsupported(_)));
    }
    for class in [3u16, 4, 255] {
        let message = query_labels(6, &[b"pypi", b"org"], TYPE_A, class);
        let reply = world.ask(&a, &message);
        assert_eq!(response(&reply, &message).code, ResponseCode::NotImp);
        assert_eq!(
            reply.outcome,
            GuardOutcome::Malformed(QueryProblem::UnsupportedClass { class })
        );
    }
    assert_eq!(world.external_calls(), 0);
}

#[test]
fn compressed_multiple_over_long_and_edns_queries_never_reach_v11() {
    let clock = clock();
    let mut world = World::new(&clock);
    let a = world.add("sbx-a", |_| {});
    let granted = query(0x4242, "pypi.org", TYPE_A);
    let mut compressed = granted[..HEADER_BYTES].to_vec();
    compressed.extend_from_slice(&[4, b'p', b'y', b'p', b'i', 0xC0, 0x0C, 0, 1, 0, 1]);
    let mut two = granted.clone();
    two[5] = 2;
    two.extend_from_slice(&question_bytes(&granted));
    let label63: &[u8] = &[b'a'; 63];
    let too_long = query_labels(1, &[label63; 4], TYPE_A, CLASS_IN);
    for (message, problem) in [
        (compressed, QueryProblem::CompressedName),
        (two, QueryProblem::QuestionCount { count: 2 }),
        (too_long, QueryProblem::NameTooLong { bytes: 257 }),
    ] {
        let reply = world.ask(&a, &message);
        let decoded = response(&reply, &message);
        assert_eq!(decoded.code, ResponseCode::FormErr);
        assert!(decoded.question.is_empty());
        assert_eq!(reply.outcome, GuardOutcome::Malformed(problem));
    }
    // EDNS: FORMERR with the question echoed, so the stub retries without OPT.
    let mut edns = granted.clone();
    edns[11] = 1;
    edns.extend_from_slice(&[0, 0, 41, 0x04, 0xD0, 0, 0, 0, 0, 0, 0]);
    let reply = world.ask(&a, &edns);
    let decoded = response(&reply, &edns);
    assert_eq!(decoded.code, ResponseCode::FormErr);
    assert_eq!(decoded.question, question_bytes(&granted));
    assert_eq!(world.external_calls(), 0);
    let reply = world.ask(&a, &granted);
    assert_eq!(response(&reply, &granted).answers.len(), 2);
}

#[test]
fn an_exhausted_name_budget_or_release_channel_is_refused() {
    let clock = clock();
    let mut world = World::new(&clock);
    let a = world.add("sbx-a", |document| {
        for grant in &mut document.egress {
            grant.budgets = budgets(2);
        }
    });
    for id in 0..2u16 {
        assert_eq!(
            world.ask(&a, &query(id, "pypi.org", TYPE_A)).code,
            Some(ResponseCode::NoError)
        );
    }
    let message = query(2, "pypi.org", TYPE_A);
    let reply = world.ask(&a, &message);
    let decoded = response(&reply, &message);
    assert_eq!(decoded.code, ResponseCode::Refused);
    assert!(decoded.answers.is_empty());
    assert!(matches!(
        refused_with(&reply),
        FlowRefusal::Destination(DestinationRefusal::Budget(_))
    ));
    assert_eq!(world.dns.calls(), 2);

    // Room for exactly two 26-byte queries on the DNS release channel.
    let mut world = World::new(&clock);
    let b = world.add("sbx-b", |document| {
        if let Some(channel) = document.release.channels.get_mut(&ReleaseChannel::DnsQuery) {
            channel.budget_bytes = 52;
        }
    });
    for id in 0..2u16 {
        assert_eq!(
            world.ask(&b, &query(id, "pypi.org", TYPE_A)).code,
            Some(ResponseCode::NoError)
        );
    }
    let reply = world.ask(&b, &query(2, "pypi.org", TYPE_A));
    assert_eq!(reply.code, Some(ResponseCode::Refused));
    assert!(matches!(
        refused_with(&reply),
        FlowRefusal::Destination(DestinationRefusal::Release(ReleaseError::Exhausted(_)))
    ));
    assert_eq!(world.dns.calls(), 2);
    assert_eq!(world.net.usage(&b, &route("pypi")).dns_queries, 2);
}

#[test]
fn refused_answers_map_to_refused_or_servfail() {
    let cases: [(Result<ResolverAnswer, ResolverFailure>, ResponseCode); 5] = [
        // Policy: an address outside the grant's perimeter prefixes, a private address.
        (answer_of(&["151.102.0.1"]), ResponseCode::Refused),
        (answer_of(&[PYPI_V4, "10.0.0.7"]), ResponseCode::Refused),
        // The resolution failed or said nothing usable.
        (
            Err(ResolverFailure::NameDoesNotExist),
            ResponseCode::ServFail,
        ),
        (Err(ResolverFailure::NoData), ResponseCode::ServFail),
        (
            Err(ResolverFailure::Failed {
                reason: "upstream timed out".to_owned(),
            }),
            ResponseCode::ServFail,
        ),
    ];
    for (result, code) in cases {
        let clock = clock();
        let mut world = World::new(&clock);
        let a = world.add("sbx-a", |_| {});
        world.dns.set("pypi.org", V4, result);
        let message = query(1, "pypi.org", TYPE_A);
        let reply = world.ask(&a, &message);
        let decoded = response(&reply, &message);
        assert_eq!(decoded.code, code);
        assert!(decoded.answers.is_empty());
        assert_eq!(refusal_code(refused_with(&reply)), code);
        // The query left, so it stays charged.
        assert_eq!(world.net.usage(&a, &route("pypi")).dns_queries, 1);
        // No binding was made: the address is not reachable.
        assert!(world.tcp(&a, PYPI_V4, 443).is_err());
    }
}

fn answer_of(addresses: &[&str]) -> Result<ResolverAnswer, ResolverFailure> {
    Ok(ResolverAnswer {
        name: name("pypi.org"),
        aliases: Vec::new(),
        addresses: addresses.iter().map(|address| ip(address)).collect(),
        ttl: Duration::from_secs(60),
    })
}

#[test]
fn only_the_grants_own_resolver_is_asked_and_its_absence_is_servfail() {
    let clock = clock();
    let mut world = World::new(&clock);
    let a = world.add("sbx-a", |_| {});
    let resolvers: [&dyn Resolver; 1] = [&world.rogue];
    let message = query(1, "pypi.org", TYPE_A);
    let reply = handle_query(&mut world.net, &a, &resolvers, &message);
    assert_eq!(response(&reply, &message).code, ResponseCode::ServFail);
    assert!(matches!(
        refused_with(&reply),
        FlowRefusal::ResolverUnavailable { .. }
    ));
    assert_eq!(world.external_calls(), 0);
}

#[test]
fn a_sandbox_v11_never_admitted_is_refused() {
    // A strict-mode or offline sandbox has no broader network profile, so V11 never
    // admits it; the guard follows V11's refusal and adds no rule of its own.
    let clock = clock();
    let mut world = World::new(&clock);
    let message = query(1, "pypi.org", TYPE_A);
    let reply = world.ask(&exec("strict-sandbox"), &message);
    let decoded = response(&reply, &message);
    assert_eq!(decoded.code, ResponseCode::Refused);
    assert_eq!(decoded.question, question_bytes(&message));
    assert!(matches!(
        reply.outcome,
        GuardOutcome::HostRefused(FlowRefusal::UnknownSandbox { .. })
    ));
    assert_eq!(world.external_calls(), 0);
}

#[test]
fn a_large_answer_is_trimmed_to_512_bytes_and_every_address_is_bound() {
    let clock = clock();
    let mut world = World::new(&clock);
    let a = world.add("sbx-a", |_| {});
    let v4: Vec<String> = (1..=40).map(|host| format!("151.101.0.{host}")).collect();
    let v6: Vec<String> = (1..=20)
        .map(|host| format!("2a04:4e42::{host:x}"))
        .collect();
    let v4_refs: Vec<&str> = v4.iter().map(String::as_str).collect();
    let v6_refs: Vec<&str> = v6.iter().map(String::as_str).collect();
    world.dns.answer("pypi.org", V4, &v4_refs, 60);
    world.dns.answer("pypi.org", V6, &v6_refs, 60);
    // "pypi.org" takes 14 question bytes: (512 - 12 - 14) / 16 = 30 A, / 28 = 17 AAAA.
    for (qtype, capacity, all) in [(TYPE_A, 30, &v4), (TYPE_AAAA, 17, &v6)] {
        let message = query(1, "pypi.org", qtype);
        let reply = world.ask(&a, &message);
        assert!(reply.response.as_ref().unwrap().len() <= MAX_MESSAGE_BYTES);
        let decoded = response(&reply, &message);
        let expected: Vec<IpAddr> = all.iter().take(capacity).map(|text| ip(text)).collect();
        let got: Vec<IpAddr> = decoded
            .answers
            .iter()
            .map(|(address, _)| *address)
            .collect();
        assert_eq!(got, expected);
        assert_eq!(sent(&reply).0, expected);
        // An address beyond the trimmed records is bound too.
        assert!(world.tcp(&a, all.last().unwrap(), 443).is_ok());
    }
    assert_eq!(
        world.net.usage(&a, &route("pypi")).dns_queries,
        2,
        "two queries, two charges"
    );
}
