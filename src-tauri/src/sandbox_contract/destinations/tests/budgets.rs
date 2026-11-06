//! VM §2.5: release channels, central reservation and the counted-bytes bound, charged
//! to CORE-05's VM-D12 general release budget.

use super::*;

const MIB: u64 = 1024 * 1024;

fn account(
    policies: &[(ReleaseChannel, u64)],
    general: GeneralReleaseBudget,
    allowance_bytes: u64,
) -> ReleaseAccount {
    ReleaseAccount::new(
        policies
            .iter()
            .map(|(channel_name, budget)| {
                (*channel_name, channel(*budget, ReleaseTrustClass::External))
            })
            .collect(),
        general,
        InFlightAllowance {
            bytes: allowance_bytes,
            documented_reason: "framing and retransmission are sized only when sent".to_owned(),
        },
    )
    .unwrap()
}

#[test]
fn counted_bytes_never_exceed_channel_budgets_plus_the_documented_allowance() {
    // counted_bytes_out <= sum(channel_budget) + documented_reserved_in_flight_allowance
    let channels = [
        (ReleaseChannel::ProviderRequest, 50_000),
        (ReleaseChannel::TransportStream, 30_000),
        (ReleaseChannel::DnsQuery, 2_000),
        (ReleaseChannel::PublishedServiceResponse, 10_000),
    ];
    for seed in 0..20u64 {
        let mut random = SplitMix64::new(seed);
        let mut release = account(&channels, GeneralReleaseBudget::vm_d12_default(), 512);
        let mut open = Vec::new();
        for _ in 0..400 {
            match random.below(3) {
                0 => {
                    let (channel_name, _) = channels[random.below(channels.len() as u64) as usize];
                    if let Ok(reservation) = release.reserve(channel_name, 1 + random.below(4_000))
                    {
                        open.push(reservation);
                    }
                }
                1 if !open.is_empty() => {
                    let reservation = open.swap_remove(random.below(open.len() as u64) as usize);
                    let reserved = reservation.bytes();
                    // Executors stop at their reservation; now and then framing adds a
                    // few bytes, which the documented allowance absorbs.
                    let actual = if random.below(8) == 0 {
                        reserved + 1 + random.below(3)
                    } else {
                        reserved.saturating_sub(random.below(4))
                    };
                    release.commit(reservation, actual).unwrap();
                }
                _ if !open.is_empty() => {
                    let reservation = open.swap_remove(random.below(open.len() as u64) as usize);
                    release.cancel(reservation).unwrap();
                }
                _ => {}
            }
            assert!(
                release.counted_bytes_out() <= release.bound_bytes(),
                "seed {seed}"
            );
            assert_eq!(
                release.general().released_bytes() + release.allowance_used_bytes(),
                release.counted_bytes_out(),
                "seed {seed}"
            );
        }
        assert_eq!(release.bound_bytes(), 92_000 + 512);
    }
}

#[test]
fn concurrent_reservations_cannot_both_spend_the_same_remainder() {
    let mut release = account(
        &[(ReleaseChannel::ProviderRequest, 1_000)],
        GeneralReleaseBudget::vm_d12_default(),
        0,
    );
    let first = release
        .reserve(ReleaseChannel::ProviderRequest, 700)
        .unwrap();
    assert!(matches!(
        release.reserve(ReleaseChannel::ProviderRequest, 400),
        Err(ReleaseError::Exhausted(BudgetExhausted {
            reserved: 700,
            requested: 400,
            ..
        }))
    ));
    release.commit(first, 600).unwrap();
    // The unused 100 bytes returned.
    assert!(release
        .reserve(ReleaseChannel::ProviderRequest, 400)
        .is_ok());
}

#[test]
fn the_vm_d12_general_budget_caps_the_sum_even_when_channels_allow_more() {
    let mut release = account(
        &[
            (ReleaseChannel::ProviderRequest, 6 * MIB),
            (ReleaseChannel::TransportStream, 6 * MIB),
        ],
        GeneralReleaseBudget::vm_d12_default(),
        0,
    );
    release
        .charge(ReleaseChannel::ProviderRequest, 6 * MIB)
        .unwrap();
    release
        .charge(ReleaseChannel::TransportStream, 2 * MIB)
        .unwrap();
    assert_eq!(release.general().remaining_bytes(), 0);
    let refusal = release
        .reserve(ReleaseChannel::TransportStream, 1)
        .unwrap_err();
    assert!(matches!(
        refusal,
        ReleaseError::Exhausted(BudgetExhausted { scope: BudgetScope::GeneralRelease, limit, .. }) if limit == 8 * MIB
    ));
}

#[test]
fn an_overrun_beyond_the_allowance_is_counted_and_stops_all_releases() {
    let mut release = account(
        &[(ReleaseChannel::TransportStream, 1_000)],
        GeneralReleaseBudget::vm_d12_default(),
        10,
    );
    let reservation = release
        .reserve(ReleaseChannel::TransportStream, 100)
        .unwrap();
    release.commit(reservation, 108).unwrap();
    assert_eq!(release.allowance_used_bytes(), 8);
    assert_eq!(release.counted_bytes_out(), 108);
    let reservation = release
        .reserve(ReleaseChannel::TransportStream, 100)
        .unwrap();
    assert_eq!(
        release.commit(reservation, 105),
        Err(ReleaseError::AllowanceExceeded {
            excess_bytes: 13,
            allowance_bytes: 10
        })
    );
    // The bytes already left, so they are counted, and the account is closed.
    assert_eq!(release.counted_bytes_out(), 213);
    assert!(release.is_closed());
    assert_eq!(
        release.reserve(ReleaseChannel::TransportStream, 1),
        Err(ReleaseError::Closed)
    );
}

#[test]
fn transfers_keep_their_own_budget_and_unlisted_channels_release_nothing() {
    let refused = ReleaseAccount::new(
        BTreeMap::from([(
            ReleaseChannel::UserApprovedTransfer,
            channel(MIB, ReleaseTrustClass::External),
        )]),
        GeneralReleaseBudget::vm_d12_default(),
        InFlightAllowance {
            bytes: 0,
            documented_reason: "none".to_owned(),
        },
    );
    assert_eq!(
        refused,
        Err(ReleaseError::OwnBudgetChannel {
            channel: ReleaseChannel::UserApprovedTransfer
        })
    );
    let mut release = release_account();
    assert_eq!(
        release.reserve(ReleaseChannel::UserApprovedTransfer, 1),
        Err(ReleaseError::OwnBudgetChannel {
            channel: ReleaseChannel::UserApprovedTransfer
        })
    );
    for unlisted in [
        ReleaseChannel::File,
        ReleaseChannel::TerminalOutput,
        ReleaseChannel::Log,
        ReleaseChannel::BrowserPreview,
    ] {
        assert_eq!(
            release.reserve(unlisted, 1),
            Err(ReleaseError::ChannelNotPermitted { channel: unlisted })
        );
    }
    let undocumented = ReleaseAccount::new(
        BTreeMap::new(),
        GeneralReleaseBudget::vm_d12_default(),
        InFlightAllowance {
            bytes: 64,
            documented_reason: "  ".to_owned(),
        },
    );
    assert_eq!(undocumented, Err(ReleaseError::UndocumentedAllowance));
}

#[test]
fn a_dns_query_releases_its_header_question_name_and_type() {
    // 12-byte header + QNAME + 4 bytes of type and class.
    let query = ResolutionQuery::new(name("api.example.com"), AddressFamily::Ipv4);
    assert_eq!(query.released_bytes(), 12 + 17 + 4);
    let long = ResolutionQuery::new(
        name("a-very-long-label-that-carries-data.attacker.example.com"),
        AddressFamily::Ipv4,
    );
    assert_eq!(
        long.released_bytes(),
        12 + long.name().wire_length_bytes() + 4
    );
}

#[test]
fn route_budget_reservations_settle_only_once_and_never_above_the_reservation() {
    let mut book = BudgetBook::new();
    let route = route_id("provider-api");
    let limits = RouteBudgets {
        dns_queries: 2,
        connections: 0,
        bytes_out: 100,
        bytes_in: 0,
        effects: 0,
    };
    let reservation = book
        .reserve(&route, &limits, BudgetKind::BytesOut, 60)
        .unwrap();
    assert_eq!(book.usage(&route).reserved(BudgetKind::BytesOut), 60);
    assert!(book
        .reserve(&route, &limits, BudgetKind::BytesOut, 41)
        .is_err());
    assert_eq!(
        book.commit(reservation, 61),
        Err(SettleError::ExceedsReservation {
            reserved: 60,
            actual: 61
        })
    );
    // The overrun is charged and the reservation closed, not left reserved.
    assert_eq!(book.usage(&route).reserved(BudgetKind::BytesOut), 0);
    assert_eq!(book.usage(&route).used(BudgetKind::BytesOut), 61);
    let mut other_book = BudgetBook::new();
    let foreign = other_book
        .reserve(&route, &limits, BudgetKind::BytesOut, 10)
        .unwrap();
    assert_eq!(book.cancel(foreign), Err(SettleError::Unknown));
    assert!(book
        .reserve(&route, &limits, BudgetKind::Connections, 1)
        .is_err());
    book.charge(&route, &limits, BudgetKind::DnsQueries, 2)
        .unwrap();
    assert_eq!(book.usage(&route).used(BudgetKind::DnsQueries), 2);
    assert!(book
        .charge(&route, &limits, BudgetKind::DnsQueries, 1)
        .is_err());
    assert_eq!(BudgetKind::ALL.len(), 5);
}
