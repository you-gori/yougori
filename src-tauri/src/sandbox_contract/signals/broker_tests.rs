//! The destination broker adapter: every class of [`DestinationRefusal`], fed through
//! V14's assessment and responder (VM part §4.2, §2.5; VM-W11; VM-W43).

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr};

use super::fixtures::*;
use super::*;
use crate::foundation::coordination::network_grant_id;
use crate::foundation::evidence::NetworkGrant;
use crate::foundation::ids::{digest, ContentKey, PolicyEpoch};
use crate::foundation::transfer::GeneralReleaseBudget;
use crate::sandbox_contract::destinations::{
    classify, AddressFamily, AddressRefused, AddressRule, Authority, AuthorizationRefusal,
    BudgetBook, BudgetExhausted, BudgetKind, BudgetScope, CanonicalName, ChannelPolicy,
    DestinationPort, DestinationRefusal, HostAddressGeneration, HostAddressState,
    InFlightAllowance, IpPrefix, ReleaseAccount, ReleaseChannel, ReleaseError, ReleaseTrustClass,
    RequestRefusal, ResolverFailure, ResolverId, RouteBudgets, RouteId, SettleError,
    SyntheticError,
};
use crate::sandbox_contract::files::{SandboxClass, ViolationAction};
use crate::sandbox_contract::response::{
    DecisionReason, HostObserver, SignalClass, SignalSource, ViolationKind,
};

fn route(name: &str) -> RouteId {
    RouteId::new(name).unwrap()
}

fn context(sandbox: &str, now: &crate::foundation::ids::ManualClock) -> BrokerContext {
    BrokerContext {
        observed: observed(sandbox, now),
        route: route("api-example"),
    }
}

fn authority(text: &str) -> Authority {
    Authority::parse(text, DestinationPort::HTTPS).unwrap()
}

fn name(text: &str) -> CanonicalName {
    CanonicalName::parse(text).unwrap()
}

fn address(text: &str) -> IpAddr {
    text.parse().unwrap()
}

fn exhausted(scope: BudgetScope) -> BudgetExhausted {
    BudgetExhausted {
        scope,
        kind: None,
        limit: 10,
        used: 10,
        reserved: 0,
        requested: 1,
    }
}

fn account(allowance_bytes: u64) -> ReleaseAccount {
    ReleaseAccount::new(
        BTreeMap::from([(
            ReleaseChannel::ProviderRequest,
            ChannelPolicy {
                budget_bytes: 1_000,
                trust_class: ReleaseTrustClass::External,
            },
        )]),
        GeneralReleaseBudget::with_limit(10_000),
        InFlightAllowance {
            bytes: allowance_bytes,
            documented_reason: "TLS framing is sized when sent".into(),
        },
    )
    .unwrap()
}

fn budgets() -> RouteBudgets {
    RouteBudgets {
        dns_queries: 10,
        connections: 10,
        bytes_out: 100,
        bytes_in: 100,
        effects: 1,
    }
}

#[test]
fn a_connection_to_an_unvalidated_address_is_a_perimeter_violation_naming_no_grant() {
    let now = clock();
    let refusal = DestinationRefusal::AddressNotValidated {
        address: address("169.254.169.254"),
    };
    let outcome = destination_refusal_signal(&refusal, &context("exe-a", &now));
    assert_eq!(outcome.cause(), Some(&BrokerViolation::UnvalidatedAddress));
    let draft = outcome.into_draft().unwrap();
    assert_eq!(
        draft.class,
        SignalClass::Violation {
            kind: ViolationKind::PerimeterRule
        }
    );
    assert_eq!(
        draft.source,
        SignalSource::HostObserved {
            observer: HostObserver::Perimeter
        }
    );
    assert_eq!(draft.subject, route_subject(&route("api-example")));
    assert_eq!(draft.violated_grant, None);
    assert_eq!(draft.observed_at, at(START_SECONDS));
    let record = respond_alone(draft, &now);
    assert_eq!(record.decision.actions, violation_actions(true));
    assert_eq!(
        record.decision.reason,
        DecisionReason::KnownViolation {
            kind: ViolationKind::PerimeterRule,
            observer: HostObserver::Perimeter,
            meaning: None
        }
    );
}

#[test]
fn an_unknown_reservation_is_host_wiring_never_a_violation() {
    let now = clock();
    // Reservations are move-only host values: presenting one an account never issued
    // takes host code, here one account's reservation presented to another.
    let mut issuing = account(0);
    let mut other = account(0);
    let reservation = issuing
        .reserve(ReleaseChannel::ProviderRequest, 10)
        .unwrap();
    let release = other.commit(reservation, 10).unwrap_err();
    assert_eq!(release, ReleaseError::UnknownReservation);
    let mut book = BudgetBook::new();
    let mut elsewhere = BudgetBook::new();
    let held = book
        .reserve(&route("api-example"), &budgets(), BudgetKind::BytesOut, 10)
        .unwrap();
    let settle = elsewhere.commit(held, 10).unwrap_err();
    assert_eq!(settle, SettleError::Unknown);
    for refusal in [
        DestinationRefusal::Release(release),
        DestinationRefusal::Settle(settle),
    ] {
        assert_eq!(
            destination_refusal_signal(&refusal, &context("exe-a", &now)),
            Classification::Ordinary {
                reason: Ordinary::HostWiring
            },
            "{refusal:?}"
        );
    }
}

#[test]
fn a_release_overrun_is_a_violation_the_broker_saw_and_the_closed_account_after_it_is_not() {
    let now = clock();
    // 30 bytes left on a 10-byte reservation, past a 5-byte allowance.
    let mut release = account(5);
    let reservation = release
        .reserve(ReleaseChannel::ProviderRequest, 10)
        .unwrap();
    let overrun = release.commit(reservation, 30).unwrap_err();
    assert!(matches!(overrun, ReleaseError::AllowanceExceeded { .. }));
    // The route book has no allowance: any byte past the reservation is an overrun.
    let mut book = BudgetBook::new();
    let held = book
        .reserve(&route("api-example"), &budgets(), BudgetKind::BytesOut, 10)
        .unwrap();
    let exceeded = book.commit(held, 11).unwrap_err();
    assert_eq!(
        exceeded,
        SettleError::ExceedsReservation {
            reserved: 10,
            actual: 11
        }
    );
    for refusal in [
        DestinationRefusal::Release(overrun),
        DestinationRefusal::Settle(exceeded),
    ] {
        let outcome = destination_refusal_signal(&refusal, &context("exe-a", &now));
        assert_eq!(outcome.cause(), Some(&BrokerViolation::ReleaseOverrun));
        let draft = outcome.into_draft().unwrap();
        assert_eq!(
            draft.class,
            SignalClass::Violation {
                kind: ViolationKind::BudgetOverrun
            }
        );
        assert_eq!(
            draft.source,
            SignalSource::HostObserved {
                observer: HostObserver::Broker
            }
        );
        assert_eq!(draft.violated_grant, None);
        let record = respond_alone(draft, &now);
        assert_eq!(record.decision.actions, violation_actions(true));
    }
    // Once closed by the overrun, the account refuses as designed: no second signal.
    let closed = release
        .reserve(ReleaseChannel::ProviderRequest, 1)
        .unwrap_err();
    assert_eq!(closed, ReleaseError::Closed);
    assert_eq!(
        destination_refusal_signal(
            &DestinationRefusal::Release(closed),
            &context("exe-a", &now)
        )
        .ordinary(),
        Some(Ordinary::NotPermitted)
    );
    // Within the allowance, nothing is refused at all.
    let mut tolerant = account(5);
    let reservation = tolerant
        .reserve(ReleaseChannel::ProviderRequest, 10)
        .unwrap();
    assert_eq!(tolerant.commit(reservation, 14), Ok(()));
}

#[test]
fn ordinary_destination_refusals_draft_no_signal() {
    let now = clock();
    let host = HostAddressState::new(HostAddressGeneration::FIRST, []);
    let loopback = classify(address("127.0.0.1"), &host);
    let metadata = classify(address("169.254.169.254"), &host);
    // A real spent route budget.
    let mut book = BudgetBook::new();
    let spent = book
        .charge(&route("api-example"), &budgets(), BudgetKind::Effects, 2)
        .unwrap_err();
    let cases = [
        (
            DestinationRefusal::Authorization(AuthorizationRefusal::Offline),
            Ordinary::NotPermitted,
        ),
        (
            DestinationRefusal::Authorization(AuthorizationRefusal::NotGranted {
                authority: authority("telemetry.example.com"),
            }),
            Ordinary::NotPermitted,
        ),
        (
            DestinationRefusal::Authorization(AuthorizationRefusal::WildcardTooDeep {
                name: name("a.b.preview.example.com"),
                zone: name("preview.example.com"),
            }),
            Ordinary::NotPermitted,
        ),
        (
            DestinationRefusal::Authorization(AuthorizationRefusal::OwnershipExpired {
                zone: name("preview.example.com"),
            }),
            Ordinary::NotCurrent,
        ),
        (
            DestinationRefusal::Authorization(AuthorizationRefusal::PortNotGranted {
                authority: authority("api.example.com:8443"),
            }),
            Ordinary::NotPermitted,
        ),
        (
            DestinationRefusal::Authorization(AuthorizationRefusal::ProtocolNotGranted {
                authority: authority("api.example.com"),
            }),
            Ordinary::NotPermitted,
        ),
        // Cloud SDKs probe the metadata endpoint routinely; asking is not a violation.
        (
            DestinationRefusal::Authorization(AuthorizationRefusal::AddressNeedsEndpointGrant {
                address: address("169.254.169.254"),
            }),
            Ordinary::NotPermitted,
        ),
        (
            DestinationRefusal::Authorization(AuthorizationRefusal::ResolutionForbidden {
                name: name("api.example.com"),
            }),
            Ordinary::NotPermitted,
        ),
        (
            DestinationRefusal::Authorization(AuthorizationRefusal::ObjectNotApproved {
                key: ContentKey::of(b"unapproved"),
            }),
            Ordinary::NotPermitted,
        ),
        (
            DestinationRefusal::Stale {
                policy_epoch: PolicyEpoch::FIRST,
                host_generation: HostAddressGeneration::FIRST,
            },
            Ordinary::NotCurrent,
        ),
        (DestinationRefusal::Expired, Ordinary::NotCurrent),
        (
            DestinationRefusal::UnknownRoute {
                route: route("removed"),
            },
            Ordinary::NotPermitted,
        ),
        (
            DestinationRefusal::ResolverNotAllowed {
                resolver: ResolverId::new("guest-chosen").unwrap(),
            },
            Ordinary::NotPermitted,
        ),
        (
            DestinationRefusal::EndpointNotResolved,
            Ordinary::HostConfiguration,
        ),
        (
            DestinationRefusal::NotAnEndpoint,
            Ordinary::HostConfiguration,
        ),
        (
            DestinationRefusal::ResolutionForbidden,
            Ordinary::NotPermitted,
        ),
        (DestinationRefusal::Ipv6NotGranted, Ordinary::NotPermitted),
        (
            DestinationRefusal::ResolverFailed(ResolverFailure::NameDoesNotExist),
            Ordinary::NotFound,
        ),
        (
            DestinationRefusal::ResolverFailed(ResolverFailure::NoData),
            Ordinary::NotFound,
        ),
        (
            DestinationRefusal::ResolverFailed(ResolverFailure::Failed {
                reason: "timeout".into(),
            }),
            Ordinary::UnusableDestination,
        ),
        (
            DestinationRefusal::AnswerForOtherName {
                asked: name("api.example.com"),
                answered: name("api.example.com.corp.local"),
            },
            Ordinary::UnusableDestination,
        ),
        (
            DestinationRefusal::WrongFamily {
                asked: AddressFamily::Ipv6,
                address: address("203.0.113.7"),
            },
            Ordinary::UnusableDestination,
        ),
        (
            DestinationRefusal::AliasChainTooLong { length: 9 },
            Ordinary::UnusableDestination,
        ),
        (
            DestinationRefusal::EmptyAnswer,
            Ordinary::UnusableDestination,
        ),
        // A refused address class came from the resolver's answer or the policy, not
        // from the guest.
        (
            DestinationRefusal::Address(AddressRefused {
                verdict: loopback,
                rule: AddressRule::ResolvedName,
            }),
            Ordinary::UnusableDestination,
        ),
        (
            DestinationRefusal::Address(AddressRefused {
                verdict: metadata,
                rule: AddressRule::ExactEndpoint,
            }),
            Ordinary::UnusableDestination,
        ),
        (
            DestinationRefusal::Synthetic(SyntheticError::Collision {
                address: address("198.18.0.9"),
                prefix: IpPrefix::new(IpAddr::V4(Ipv4Addr::new(198, 18, 0, 0)), 15).unwrap(),
            }),
            Ordinary::UnusableDestination,
        ),
        (
            DestinationRefusal::Synthetic(SyntheticError::Exhausted {
                family: AddressFamily::Ipv4,
            }),
            Ordinary::LimitReached,
        ),
        (
            DestinationRefusal::Synthetic(SyntheticError::NoIpv6Range),
            Ordinary::HostConfiguration,
        ),
        (
            DestinationRefusal::Synthetic(SyntheticError::UnsuitableCandidate {
                prefix: IpPrefix::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 0)), 24).unwrap(),
            }),
            Ordinary::HostConfiguration,
        ),
        (
            DestinationRefusal::Synthetic(SyntheticError::NoUsableCandidate {
                family: AddressFamily::Ipv4,
                skipped: Vec::new(),
            }),
            Ordinary::HostConfiguration,
        ),
        (DestinationRefusal::Budget(spent), Ordinary::LimitReached),
        (
            DestinationRefusal::Release(ReleaseError::Exhausted(exhausted(
                BudgetScope::GeneralRelease,
            ))),
            Ordinary::LimitReached,
        ),
        (
            DestinationRefusal::Release(ReleaseError::ChannelNotPermitted {
                channel: ReleaseChannel::Log,
            }),
            Ordinary::NotPermitted,
        ),
        (
            DestinationRefusal::Release(ReleaseError::OwnBudgetChannel {
                channel: ReleaseChannel::UserApprovedTransfer,
            }),
            Ordinary::NotPermitted,
        ),
        (
            DestinationRefusal::Release(ReleaseError::UndocumentedAllowance),
            Ordinary::HostConfiguration,
        ),
        (
            DestinationRefusal::Redirect(RequestRefusal::SchemeNotHttps),
            Ordinary::UnusableDestination,
        ),
        (
            DestinationRefusal::RedirectsDisabled,
            Ordinary::NotPermitted,
        ),
        (
            DestinationRefusal::RedirectLeavesRoute {
                from: route("api-example"),
                to: route("other"),
            },
            Ordinary::NotPermitted,
        ),
        (DestinationRefusal::NotNewer, Ordinary::HostConfiguration),
    ];
    let mut reasons = BTreeSet::new();
    for (refusal, reason) in cases {
        let outcome = destination_refusal_signal(&refusal, &context("exe-a", &now));
        assert_eq!(outcome, Classification::Ordinary { reason }, "{refusal:?}");
        reasons.insert(reason);
    }
    assert_eq!(reasons.len(), 6);
}

#[test]
fn a_guests_own_route_misuse_stops_it_and_revokes_nothing_in_a_sandbox_sharing_the_route() {
    let now = clock();
    // Every sandbox holding the route holds the same CORE-04 grant identity.
    let shared = network_grant_id(&NetworkGrant::NamedRoute {
        route: digest("yougori/test/route/v1", &[b"api-example"]),
    });
    for refusal in [
        DestinationRefusal::AddressNotValidated {
            address: address("10.0.0.5"),
        },
        DestinationRefusal::Release(ReleaseError::AllowanceExceeded {
            excess_bytes: 100,
            allowance_bytes: 10,
        }),
    ] {
        let draft = destination_refusal_signal(&refusal, &context("exe-a", &now))
            .into_draft()
            .unwrap();
        let assessment = assess(&[signal(draft)], &now);
        assert_eq!(assessment.violated_grant(), None);
        let mut responder = responder_with(
            &now,
            &[
                ("exe-a", SandboxClass::Service, &[shared]),
                ("exe-b", SandboxClass::Task, &[shared]),
            ],
        );
        let record = responded(responder.respond_to(&assessment).unwrap());
        assert_eq!(record.targets.len(), 1, "{refusal:?}");
        let observed = record.observed().unwrap();
        assert_eq!(observed.sandbox, execution("exe-a"));
        assert_eq!(observed.actions, violation_actions(true));
        // A service sandbox locks down with a one-click stop instead of stopping.
        assert_eq!(observed.class_response, Some(ViolationAction::LockDown));
        assert_eq!(
            responder.applied(&execution("exe-b")),
            Some(&BTreeSet::new())
        );
    }
}
