//! The perimeter model behind the VM-N3 network faults (guest policy ignored, stale DNS
//! answer, relay identity spoofed, firewall rule missing; VM-P06, VM-P07, VM-P11, VM-P29).
//!
//! Sandbox A sends one request, directly or through the host relay. The relay accepts
//! only names on the requesting sandbox's list and checks the answer it decided on; with
//! the address check it also checks the address it actually connects to. Sandbox B's list
//! contains a name whose address A may not reach. A rebinding name is on A's list but
//! resolves to a forbidden address.
//!
//! Bounds: one request per run. Assumptions: the relay refuses literal addresses (named
//! routes only); a stale answer is the earlier, allowed answer of the rebinding name;
//! spoofing a claimed identity needs guest root.

use std::fmt;

use super::contract::{Defect, Guard, Injection, InvariantId, ModelConfig, ModelKind};
use super::explore::TransitionSystem;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Target {
    AllowedName,
    OtherTenantName,
    RebindingName,
    ForbiddenAddress,
}

impl Target {
    const ALL: [Self; 4] = [
        Self::AllowedName,
        Self::OtherTenantName,
        Self::RebindingName,
        Self::ForbiddenAddress,
    ];

    fn label(self) -> &'static str {
        match self {
            Self::AllowedName => "allowed name",
            Self::OtherTenantName => "other-tenant name",
            Self::RebindingName => "rebinding name",
            Self::ForbiddenAddress => "forbidden address",
        }
    }

    /// The destination class a connection made now reaches.
    fn connected(self) -> Destination {
        match self {
            Self::AllowedName => Destination::Allowed,
            Self::OtherTenantName => Destination::OtherTenantOnly,
            Self::RebindingName | Self::ForbiddenAddress => Destination::Forbidden,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Route {
    Relay,
    Direct,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(super) enum Destination {
    Allowed,
    OtherTenantOnly,
    Forbidden,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(super) enum EgressState {
    Idle,
    Delivered(Destination),
    Dropped,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Send {
    route: Route,
    target: Target,
    spoofed: bool,
}

impl fmt::Display for Send {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let route = match self.route {
            Route::Relay => "via relay",
            Route::Direct => "directly",
        };
        write!(f, "send {} {route}", self.target.label())?;
        if self.spoofed {
            f.write_str(" spoofing identity")?;
        }
        Ok(())
    }
}

pub(super) struct EgressModel<'c> {
    config: &'c ModelConfig,
}

impl<'c> EgressModel<'c> {
    pub(super) fn new(config: &'c ModelConfig) -> Self {
        Self { config }
    }

    fn decide(&self, send: Send) -> EgressState {
        let config = self.config;
        match send.route {
            Route::Direct => {
                if config.enforces(Guard::GuestEgressPolicy) || config.enforces(Guard::HostFirewall)
                {
                    EgressState::Dropped
                } else {
                    EgressState::Delivered(send.target.connected())
                }
            }
            Route::Relay => {
                let channel_identity = config.enforces(Guard::RelayChannelIdentity)
                    && !config.defect(Defect::RelayTrustsClaimedIdentity);
                let as_other_tenant = send.spoofed && !channel_identity;
                let listed = match send.target {
                    Target::AllowedName => true,
                    Target::OtherTenantName => as_other_tenant,
                    Target::RebindingName => !as_other_tenant,
                    Target::ForbiddenAddress => false,
                };
                if !listed {
                    return EgressState::Dropped;
                }
                let decided = match send.target {
                    Target::RebindingName if config.has(Injection::StaleDnsAnswer) => {
                        Destination::Allowed
                    }
                    other => other.connected(),
                };
                if decided == Destination::Forbidden {
                    return EgressState::Dropped;
                }
                let connected = send.target.connected();
                let address_checked = config.enforces(Guard::RelayAddressCheck)
                    && !config.defect(Defect::AllowDecisionCachedByName);
                if address_checked && connected == Destination::Forbidden {
                    EgressState::Dropped
                } else {
                    EgressState::Delivered(connected)
                }
            }
        }
    }
}

impl TransitionSystem for EgressModel<'_> {
    type State = EgressState;
    type Action = Send;

    fn kind(&self) -> ModelKind {
        ModelKind::Egress
    }

    fn initial_states(&self) -> Vec<EgressState> {
        vec![EgressState::Idle]
    }

    fn successors(&self, state: &EgressState) -> Vec<(Send, EgressState)> {
        if *state != EgressState::Idle {
            return Vec::new();
        }
        let config = self.config;
        let mut sends = vec![Send {
            route: Route::Relay,
            target: Target::AllowedName,
            spoofed: false,
        }];
        let hostile = config.has(Injection::HostileGuest);
        if hostile || config.has(Injection::UnprivilegedGuestCode) {
            for target in Target::ALL {
                for route in [Route::Relay, Route::Direct] {
                    sends.push(Send {
                        route,
                        target,
                        spoofed: false,
                    });
                }
                if hostile && config.has(Injection::RelayIdentitySpoofed) {
                    sends.push(Send {
                        route: Route::Relay,
                        target,
                        spoofed: true,
                    });
                }
            }
        }
        sends.dedup();
        sends
            .into_iter()
            .map(|send| (send, self.decide(send)))
            .collect()
    }

    fn holds(&self, invariant: InvariantId, state: &EgressState) -> bool {
        match invariant {
            InvariantId::NoForbiddenEgress => !matches!(
                state,
                EgressState::Delivered(Destination::OtherTenantOnly | Destination::Forbidden)
            ),
            _ => true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sandbox_contract::models::contract::check_model;
    use crate::sandbox_contract::models::explore::{Bounds, Exploration};

    fn check(config: &ModelConfig) -> Exploration {
        check_model(ModelKind::Egress, config, Bounds::DEFAULT).unwrap()
    }

    fn first_step(result: &Exploration) -> String {
        result
            .violation(InvariantId::NoForbiddenEgress)
            .map(|violation| violation.trace.steps.join(", "))
            .unwrap_or_default()
    }

    #[test]
    fn the_perimeter_holds_under_the_threat_model() {
        for config in [ModelConfig::correct(), ModelConfig::threat_model()] {
            let result = check(&config);
            assert!(result.complete);
            assert!(result.is_clean(), "{:?}", result.violations);
        }
    }

    #[test]
    fn each_host_guard_is_a_single_point_against_guest_root() {
        let threat = ModelConfig::threat_model();
        let cases = [
            (Guard::HostFirewall, "send other-tenant name directly"),
            (
                Guard::RelayChannelIdentity,
                "send other-tenant name via relay spoofing identity",
            ),
            (Guard::RelayAddressCheck, "send rebinding name via relay"),
        ];
        for (guard, step) in cases {
            assert_eq!(
                first_step(&check(&threat.clone().without_guards([guard]))),
                step
            );
        }
        // The guest-side policy is no wall against guest root.
        assert!(check(&threat.without_guards([Guard::GuestEgressPolicy])).is_clean());
    }

    #[test]
    fn guest_policy_still_binds_unprivileged_code() {
        let unprivileged =
            ModelConfig::correct().with_injections([Injection::UnprivilegedGuestCode]);
        assert!(check(&unprivileged.clone().without_guards([Guard::HostFirewall])).is_clean());
        let both = unprivileged.without_guards([Guard::HostFirewall, Guard::GuestEgressPolicy]);
        assert!(!check(&both).is_clean());
    }

    #[test]
    fn seeded_relay_defects_leak_to_forbidden_destinations() {
        let hostile = ModelConfig::correct().with_injections([Injection::HostileGuest]);
        let spoofing = hostile
            .clone()
            .with_injections([Injection::RelayIdentitySpoofed]);
        let stale = hostile.with_injections([Injection::StaleDnsAnswer]);
        assert!(check(&spoofing).is_clean() && check(&stale).is_clean());
        assert_eq!(
            first_step(&check(
                &spoofing.with_defects([Defect::RelayTrustsClaimedIdentity])
            )),
            "send other-tenant name via relay spoofing identity"
        );
        assert_eq!(
            first_step(&check(
                &stale.with_defects([Defect::AllowDecisionCachedByName])
            )),
            "send rebinding name via relay"
        );
    }
}
