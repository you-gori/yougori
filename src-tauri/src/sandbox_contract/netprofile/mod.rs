//! V11: the broader VM network profile (VM-W59) and the host side of guest network
//! compatibility (VM-W08) (docs/combined-gpu-memory-and-vm-sandbox-plan.md, VM part §1.3,
//! §4.1–§4.4 and §4.7; VM-W13 and VM-W15 for context; scenarios VM-P08, VM-P09 and
//! VM-P36; controls VM-CP-08 and VM-CP-09; Tier 0, §12.1).
//!
//! This is the policy and decision model only. It enforces nothing on a real NIC,
//! firewall or VM: it composes V02 (`destinations`) decisions for one whole VM and models
//! the host's NAT and connection-tracking view on fakes. Wiring it into the full-VM
//! network device (`runtime/vm.rs`), the microVM filter (`runtime/microvm_network.rs`),
//! the `sandbox-host` packet mode, the guest proxy environment (`appliance/agent/`) and
//! the installed platform perimeter is later work owned by VM-W59, VM-W08 and VM-W15
//! integration. Nothing here resolves a name, opens a socket or installs a rule; time
//! comes from [`crate::foundation::ids::Clock`] and resolution from V02's
//! [`Resolver`](crate::sandbox_contract::destinations::Resolver) trait.
//!
//! - [`document`]: the strict, versioned [`NetworkProfile`] of a broader-network VM
//!   (declared transport or user-owned general VM): network identity, egress as V02
//!   transport grants by exact name or exact endpoint, allowed resolvers, private
//!   exceptions only as endpoint grants with a recorded reason, publications, two-ended
//!   sandbox links, flow quotas and release budgets. Its digest is its identity and is
//!   what [`NetworkMode::UserOwnedGeneralVm`] names. A broader profile never holds the
//!   strict mode's claims (§4.1).
//! - [`pool`]: the host's sandbox address pool: host-assigned guest addresses, the host
//!   listener (gateway) addresses and the NAT port blocks.
//! - [`perimeter`]: the profile compiled into V02 [`PerimeterRule`]s and a
//!   [`PerimeterProfile`], checked with [`check_rules`], so the independent perimeter
//!   (§4.4) enforces the same egress policy as the host model. A grant the platform
//!   perimeter cannot express fails the claim; nothing is widened to make it fit.
//! - [`host`] and [`flows`]: the host-side flow model. Each new flow is decided against
//!   the profile at the current policy epoch; established flows are tracked; a reconnect
//!   is a new flow; revocation lists every flow to close; NAT mappings are deterministic
//!   and never rewrite a destination; DNS goes only through allowed resolvers and an
//!   unauthorized name causes no external query; published responses are charged to the
//!   release account.
//! - [`guest`]: proxy-first guest configuration, with a guest TUN stack or synthetic
//!   names only under a recorded justification. The host never reads it (VM-P09).
//! - [`report`]: the network-authority facet of the profile, entry by entry, never a
//!   score (§1.3).
//!
//! Claims. A profile, a compiled perimeter and a flow decision describe policy. None of
//! them is evidence that a mechanism enforces it: perimeter rules count only through
//! CORE-01 `PerimeterRuleEnforced` evidence ([`CompiledPerimeter::launch_perimeter`]),
//! and the flow model decides on fakes.
//!
//! [`NetworkMode::UserOwnedGeneralVm`]: crate::sandbox_contract::destinations::NetworkMode::UserOwnedGeneralVm
//! [`PerimeterRule`]: crate::sandbox_contract::destinations::PerimeterRule
//! [`PerimeterProfile`]: crate::sandbox_contract::destinations::PerimeterProfile
//! [`check_rules`]: crate::sandbox_contract::destinations::check_rules

/// Defines an internally tagged, snake_case enum whose deserialization refuses unknown
/// fields for every variant, unit variants included. serde ignores unknown fields beside
/// the tag of a unit variant even with `deny_unknown_fields`, so reading goes through a
/// twin enum whose unit variants are empty struct variants. Copied from
/// `strict_policy_enum!` in `sandbox_contract/policy/mod.rs`, kept local.
macro_rules! strict_netprofile_enum {
    (
        $(#[$meta:meta])*
        $vis:vis enum $name:ident tag $tag:literal {
            $(
                $(#[$variant_meta:meta])*
                $variant:ident $({
                    $(
                        $(#[$field_meta:meta])*
                        $field:ident : $ty:ty
                    ),* $(,)?
                })?
            ),* $(,)?
        }
    ) => {
        $(#[$meta])*
        #[derive(serde::Serialize)]
        #[serde(tag = $tag, rename_all = "snake_case")]
        $vis enum $name {
            $(
                $(#[$variant_meta])*
                $variant $({ $($(#[$field_meta])* $field : $ty),* })?
            ),*
        }

        impl<'de> serde::Deserialize<'de> for $name {
            fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                #[derive(serde::Deserialize)]
                #[serde(tag = $tag, rename_all = "snake_case", deny_unknown_fields)]
                enum Strict {
                    $($variant { $($($field : $ty),*)? }),*
                }
                let record = crate::foundation::strict_serde::read_tagged(deserializer, $tag)?;
                let strict = <Strict as serde::Deserialize>::deserialize(record)
                    .map_err(serde::de::Error::custom)?;
                Ok(match strict {
                    $(Strict::$variant { $($($field),*)? } => Self::$variant $({ $($field),* })?),*
                })
            }
        }
    };
}

pub mod document;
pub mod flows;
pub mod guest;
pub mod host;
pub mod perimeter;
pub mod pool;
pub mod report;

#[cfg(test)]
mod tests;

pub use document::{
    AllowedResolver, ApplicationName, BroaderNetworkKind, DataClass, EgressGrant, EgressProtocol,
    EgressTarget, FlowQuotas, GuestCompatibility, ImplementationName, Justification, LinkDirection,
    LinkEntry, LinkPeer, NetworkIdentity, NetworkProfile, NetworkProfileDocument, ProfileError,
    ProfileModeError, ProfileReadError, ProfileVersion, ProxyOffer, PublicationAudience,
    PublicationAuthentication, PublicationEntry, RecordedText, ReleaseBudgets, ResolverUpstream,
    TextError, MAX_EGRESS_GRANTS, MAX_LINKS, MAX_PERIMETER_PREFIXES, MAX_PUBLICATIONS,
    MAX_RESOLVERS, MAX_RESOLVER_UPSTREAMS, MIN_IPV4_PERIMETER_PREFIX_LENGTH,
    MIN_IPV6_PERIMETER_PREFIX_LENGTH, NETWORK_PROFILE_VERSION,
};
pub use flows::{
    CloseReason, ClosedFlow, DnsAnswer, FlowAdmission, FlowId, FlowKey, FlowKind, FlowRecord,
    FlowRefusal, NatError, NatMapping, NatScope, NatTable, ProxyListener, Revocation,
    RouteUsageView, Transport,
};
pub use guest::{guest_plan, GuestNetworkPlan, GuestPlanError, SyntheticRangePlan, TunPlan};
pub use host::{AdmitError, HostNetwork, ReplaceError};
pub use perimeter::{
    compile_perimeter, CompiledPerimeter, HostTransportDecision, PerimeterBase,
    PerimeterCapabilities, PerimeterGap, RuleSource,
};
pub use pool::{NatConfig, PoolConfig, PoolError, SandboxAddressPool};
pub use report::{AuthorityEntry, NetworkAuthorityReport};
