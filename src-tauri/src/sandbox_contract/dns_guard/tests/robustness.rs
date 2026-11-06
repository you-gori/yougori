//! No byte sequence makes the parser or the guard panic, every response stays within the
//! fixed shape, and only granted names ever reach the resolver.

use super::*;

const GRANTED: [&str; 2] = ["pypi.org", "github.com"];

/// A host with one sandbox whose budgets are large enough that random input reaches
/// resolution.
fn roomy_world(clock: &ManualClock) -> (World<'_>, ExecutionId) {
    let mut world = World::new(clock);
    let sandbox = world.add("sbx-a", |document| {
        for grant in &mut document.egress {
            grant.budgets = budgets(1_000_000);
        }
        if let Some(channel) = document.release.channels.get_mut(&ReleaseChannel::DnsQuery) {
            channel.budget_bytes = 4_000_000;
        }
    });
    (world, sandbox)
}

/// Runs `message` through the guard and checks the reply's invariants.
fn check(world: &mut World<'_>, sandbox: &ExecutionId, message: &[u8]) -> GuardReply {
    let before = world.dns.calls();
    let reply = world.ask(sandbox, message);
    match &reply.response {
        None => {
            assert_eq!(reply.code, None);
            assert!(matches!(reply.outcome, GuardOutcome::Dropped(_)));
            assert!(message.len() < HEADER_BYTES || message[2] & 0x80 != 0);
        }
        Some(response) => {
            let decoded = decode(response);
            assert_eq!(decoded.id, u16::from_be_bytes([message[0], message[1]]));
            assert_eq!(Some(decoded.code), reply.code);
            // A question is echoed exactly as it appears in the query.
            if !decoded.question.is_empty() {
                assert_eq!(
                    &message[HEADER_BYTES..HEADER_BYTES + decoded.question.len()],
                    decoded.question.as_slice()
                );
            }
            if !decoded.answers.is_empty() {
                let GuardOutcome::Decided { sent, .. } = &reply.outcome else {
                    panic!("records without a decision: {:?}", reply.outcome);
                };
                let records: Vec<IpAddr> = decoded
                    .answers
                    .iter()
                    .map(|(address, _)| *address)
                    .collect();
                assert_eq!(&records, sent);
            }
        }
    }
    for queried in world.dns.queried_since(before) {
        assert!(GRANTED.contains(&queried.name().as_str()));
    }
    assert_eq!(world.rogue.calls(), 0);
    reply
}

fn base_queries() -> Vec<Vec<u8>> {
    let label63: &[u8] = &[b'a'; 63];
    let label61: &[u8] = &[b'b'; 61];
    let mut edns = query(0x5151, "pypi.org", TYPE_A);
    edns[11] = 1;
    edns.extend_from_slice(&[0, 0, 41, 0x04, 0xD0, 0, 0, 0, 0, 0, 0]);
    vec![
        query(0x1111, "pypi.org", TYPE_A),
        query(0x2222, "PyPI.Org", TYPE_AAAA),
        query(0x3333, "registry.corp.internal", TYPE_A),
        query(0x4444, "secret.attacker.example.net", TYPE_A),
        query_labels(
            0x6161,
            &[label63, label63, label63, label61],
            TYPE_A,
            CLASS_IN,
        ),
        edns,
    ]
}

#[test]
fn every_truncation_of_a_query_is_refused_without_panicking() {
    let clock = clock();
    let (mut world, sandbox) = roomy_world(&clock);
    for message in base_queries() {
        for length in 0..message.len() {
            let prefix = &message[..length];
            assert!(
                parse_query(prefix).is_err(),
                "a prefix of {length} bytes parsed"
            );
            let reply = check(&mut world, &sandbox, prefix);
            assert!(!matches!(reply.outcome, GuardOutcome::Decided { .. }));
        }
    }
    assert_eq!(world.external_calls(), 0, "no truncated query reached V11");
}

#[test]
fn random_byte_strings_never_panic_and_never_reach_the_resolver() {
    let clock = clock();
    let (mut world, sandbox) = roomy_world(&clock);
    let mut random = SplitMix64::new(0x00D1_5EA5_ED00_0001);
    for _ in 0..20_000 {
        let length = usize::try_from(random.below(600)).unwrap();
        let mut message: Vec<u8> = (0..length).map(|_| random.byte()).collect();
        // Half the time, make it look like a query header so deeper paths are reached.
        if length >= HEADER_BYTES && random.below(2) == 0 {
            message[2] &= 0x01;
            message[3] &= 0x30;
            message[4] = 0;
            message[5] = 1;
            message[6..12].fill(0);
        }
        check(&mut world, &sandbox, &message);
    }
}

#[test]
fn mutated_queries_never_panic_and_only_granted_names_are_resolved() {
    let clock = clock();
    let (mut world, sandbox) = roomy_world(&clock);
    let bases = base_queries();
    let mut random = SplitMix64::new(0x00D1_5EA5_ED00_0002);
    let (mut answered, mut unanswered, mut malformed, mut dropped) = (0, 0, 0, 0);
    for _ in 0..20_000 {
        let base = &bases[usize::try_from(random.below(6)).unwrap()];
        let mut message = base.clone();
        for _ in 0..=random.below(4) {
            let length = u64::try_from(message.len()).unwrap();
            let index = usize::try_from(random.below(length)).unwrap();
            match random.below(4) {
                0 => message[index] ^= 1 << random.below(8),
                1 => message[index] = random.byte(),
                2 => message.truncate(index),
                _ => message.insert(index, random.byte()),
            }
            if message.is_empty() {
                break;
            }
        }
        let reply = check(&mut world, &sandbox, &message);
        match reply.outcome {
            GuardOutcome::Decided { sent, .. } if !sent.is_empty() => answered += 1,
            GuardOutcome::Dropped(_) => dropped += 1,
            GuardOutcome::Malformed(_) => malformed += 1,
            _ => unanswered += 1,
        }
    }
    // Every path was exercised: id and case flips keep a granted name granted, other
    // flips give ungranted or unwritable names, malformed messages and responses.
    assert!(answered > 0 && unanswered > 0 && malformed > 0 && dropped > 0);
}
