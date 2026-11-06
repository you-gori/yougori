//! Guest network compatibility (VM-W08; VM §4.1, lines 1938–1940).
//!
//! Proxy first: the guest is configured with standard proxy variables pointing at the
//! host's HTTP CONNECT and SOCKS5 listeners and with the host DNS listener as its only
//! resolver. A guest TUN stack and synthetic names are guest-side compatibility layers
//! offered only under a recorded [`Justification`](super::document::Justification); both
//! turn connections into proxy requests inside the guest. A synthetic range is chosen
//! by V02 [`SyntheticAddressPlan::choose`] with explicit collision handling.
//!
//! The plan is advice to the guest and nothing more. The host never reads it: a flow that
//! ignores the proxy, a raw socket, a direct IP connection and DNS to another resolver
//! are decided by [`HostNetwork`](super::host::HostNetwork) from the profile's grants
//! alone, exactly as if the plan did not exist (VM-P09).

use std::collections::BTreeSet;
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

use crate::sandbox_contract::destinations::{
    HostAddressState, IpPrefix, SkippedCandidate, SyntheticAddressPlan, SyntheticError,
};

use super::document::{ApplicationName, ImplementationName, NetworkProfile, RecordedText};
use super::pool::SandboxAddressPool;

/// What the guest is told about a justified TUN stack.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TunPlan {
    pub implementation: ImplementationName,
    pub applications: BTreeSet<ApplicationName>,
    pub reason: RecordedText,
}

/// What the guest is told about justified synthetic names: the ranges V02 chose, the
/// candidates it skipped because they collided, and the justification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SyntheticRangePlan {
    pub ipv4_range: IpPrefix,
    pub ipv6_range: Option<IpPrefix>,
    pub resolver_ipv4: Ipv4Addr,
    pub skipped: Vec<SkippedCandidate>,
    pub implementation: ImplementationName,
    pub applications: BTreeSet<ApplicationName>,
    pub reason: RecordedText,
}

/// The guest's network configuration (VM-W08), for the guest agent to apply later.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GuestNetworkPlan {
    /// The host DNS listener: the gateway address, port 53.
    pub dns_server_ipv4: Ipv4Addr,
    pub dns_server_ipv6: Option<Ipv6Addr>,
    /// Proxy variables, in a fixed order.
    pub proxy_environment: Vec<(String, String)>,
    pub tun: Option<TunPlan>,
    pub synthetic: Option<SyntheticRangePlan>,
}

impl GuestNetworkPlan {
    /// What the plan does not do, for every view that shows it.
    pub const HOST_INDEPENDENCE: &'static str = "the host decides every flow from the \
        profile's grants; guest proxy settings, a guest TUN stack and synthetic names change \
        no host decision";
}

/// Why no guest plan could be made.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GuestPlanError {
    /// The pool has no gateway address.
    NoGateway,
    Synthetic(SyntheticError),
}

impl fmt::Display for GuestPlanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoGateway => f.write_str("the sandbox pool has no gateway address"),
            Self::Synthetic(error) => fmt::Display::fmt(error, f),
        }
    }
}

impl std::error::Error for GuestPlanError {}

/// Guest-local names that bypass the proxy; nothing else does.
const NO_PROXY: &str = "localhost,127.0.0.1,::1";

/// Builds the guest plan for `profile` on this host's pool. A synthetic range avoids the
/// host's own addresses, the sandbox pool, every endpoint and every resolver upstream.
pub fn guest_plan(
    profile: &NetworkProfile,
    pool: &SandboxAddressPool,
    host: &HostAddressState,
) -> Result<GuestNetworkPlan, GuestPlanError> {
    let gateway = pool.gateway_ipv4().ok_or(GuestPlanError::NoGateway)?;
    let guest = &profile.document().guest;
    let config = pool.config();
    let mut environment = Vec::new();
    if guest.proxy.http_connect {
        let url = format!("http://{gateway}:{}", config.http_proxy_port);
        for key in ["HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"] {
            environment.push((key.to_owned(), url.clone()));
        }
    }
    if guest.proxy.socks5 {
        let url = format!("socks5h://{gateway}:{}", config.socks_proxy_port);
        for key in ["ALL_PROXY", "all_proxy"] {
            environment.push((key.to_owned(), url.clone()));
        }
    }
    for key in ["NO_PROXY", "no_proxy"] {
        environment.push((key.to_owned(), NO_PROXY.to_owned()));
    }
    let tun = guest.tun.as_ref().map(|justification| TunPlan {
        implementation: justification.implementation.clone(),
        applications: justification.applications.clone(),
        reason: justification.reason.clone(),
    });
    let synthetic = match &guest.synthetic_names {
        None => None,
        Some(justification) => {
            let mut reserved = pool.prefixes();
            reserved.extend(
                profile
                    .egress()
                    .iter()
                    .filter_map(|grant| grant.target.endpoint_address())
                    .map(IpPrefix::host),
            );
            reserved.extend(
                profile
                    .document()
                    .resolvers
                    .iter()
                    .flat_map(|resolver| resolver.upstream.iter())
                    .map(|upstream| IpPrefix::host(upstream.address)),
            );
            let ipv6_candidates: &[IpPrefix] = if profile.identity().ipv6.is_some() {
                &config.synthetic_ipv6_candidates
            } else {
                &[]
            };
            let plan = SyntheticAddressPlan::choose(
                &config.synthetic_ipv4_candidates,
                ipv6_candidates,
                host,
                &reserved,
            )
            .map_err(GuestPlanError::Synthetic)?;
            Some(SyntheticRangePlan {
                ipv4_range: plan.ipv4_range(),
                ipv6_range: plan.ipv6_range(),
                resolver_ipv4: plan.resolver_ipv4(),
                skipped: plan.skipped().to_vec(),
                implementation: justification.implementation.clone(),
                applications: justification.applications.clone(),
                reason: justification.reason.clone(),
            })
        }
    };
    Ok(GuestNetworkPlan {
        dns_server_ipv4: gateway,
        dns_server_ipv6: if profile.identity().ipv6.is_some() {
            pool.gateway_ipv6()
        } else {
            None
        },
        proxy_environment: environment,
        tun,
        synthetic,
    })
}
