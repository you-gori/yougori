//! The profile compiled into an independent perimeter (VM-W59 "independent perimeter
//! explicit"; VM §4.4; VM-W15).
//!
//! The perimeter limits what a compromised host transport could do, so it must permit no
//! more than the host model and block what the profile forbids. [`compile_perimeter`]
//! turns the profile into V02 [`PerimeterRule`]s: an allow rule for each exact endpoint,
//! each perimeter prefix of a name grant and each resolver upstream, each scoped to its
//! port; and block rules for every metadata address, every host-owned prefix and the
//! sandbox pool. The set is checked with V02 [`check_rules`] and declared as a V02
//! [`PerimeterProfile`]. Default deny is implicit.
//!
//! A grant the platform perimeter cannot express is a [`PerimeterGap`] and the claim
//! fails: a name grant without perimeter prefixes is never widened to "any public
//! address on that port", and a port-scoped rule is never widened to all ports.
//!
//! Compiling installs nothing and proves nothing. A rule counts as enforced only through
//! CORE-01 `PerimeterRuleEnforced` evidence for its own subject, which V01 judges from
//! [`CompiledPerimeter::launch_perimeter`].

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::net::IpAddr;

use crate::foundation::evidence::ConfigurationFingerprint;
use crate::foundation::ids::Digest;
use crate::sandbox_contract::destinations::{
    check_rules, DestinationPort, HostAddressState, IpPrefix, PerimeterError, PerimeterOptions,
    PerimeterPlatform, PerimeterProfile, PerimeterProperty, PerimeterRule, PerimeterTarget,
    PortSelector, RemoteEnforcement, ResolverId, RouteId, RuleAction, ServiceIdentity,
    METADATA_IPV4, METADATA_IPV6,
};
use crate::sandbox_contract::policy::LaunchPerimeter;

use super::document::{EgressTarget, LinkDirection, NetworkProfile};
use super::pool::SandboxAddressPool;

/// The V02 perimeter declaration the compiled rules go into: platform, options,
/// declared properties, remote enforcement point and the broker identity it constrains.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PerimeterBase {
    pub platform: PerimeterPlatform,
    pub options: PerimeterOptions,
    pub declared: BTreeSet<PerimeterProperty>,
    pub remote: Option<RemoteEnforcement>,
    pub broker_identity: Digest,
}

/// What the platform perimeter can express (VM §4.4). The host states these from the
/// platform's verified enforcement API; nothing here probes them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PerimeterCapabilities {
    pub ipv4_rules: bool,
    pub ipv6_rules: bool,
    /// Rules can be limited to one destination port.
    pub port_scoped_rules: bool,
    pub max_rules: u32,
}

/// Where one compiled rule came from.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RuleSource {
    Endpoint { route: RouteId },
    PerimeterPrefix { route: RouteId },
    ResolverUpstream { resolver: ResolverId },
    Metadata,
    HostOwned,
    SandboxPool,
}

/// A decision the host transport makes that never crosses the perimeter, listed so the
/// perimeter is not taken to enforce it.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum HostTransportDecision {
    /// A publication: inbound, mediated by the host's ingress.
    Publication {
        service: ServiceIdentity,
        port: DestinationPort,
    },
    /// A sandbox link: forwarded between VMs by the host transport.
    SandboxLink {
        direction: LinkDirection,
        service: ServiceIdentity,
        port: DestinationPort,
    },
    /// The DNS and proxy listeners on the gateway.
    GatewayListeners,
}

/// Why the perimeter cannot enforce the profile; the claim fails.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PerimeterGap {
    /// A name grant pins no prefix, so the perimeter could only permit it by permitting
    /// every public address on its port.
    NameGrantWithoutPerimeterPrefixes {
        route: RouteId,
    },
    Ipv4RulesUnsupported,
    /// The profile's IPv6 rules (at least the IPv6 metadata blocks) cannot be expressed.
    Ipv6RulesUnsupported,
    /// The allow rules are port-scoped and the platform cannot scope by port.
    PortScopingUnsupported,
    TooManyRules {
        needed: usize,
        max: u32,
    },
    /// A block rule overlaps an allow rule, for example because the host now owns a
    /// granted endpoint (V02 [`check_rules`]).
    Contradictory(PerimeterError),
    /// The V02 profile declaration refused (a missing platform property, a remote
    /// enforcement mismatch, an operator firewall offered as independent).
    Declaration(PerimeterError),
}

impl fmt::Display for PerimeterGap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NameGrantWithoutPerimeterPrefixes { route } => write!(
                f,
                "route {route} names no perimeter prefix; the perimeter cannot enforce it \
                 without permitting every public address on its port"
            ),
            Self::Ipv4RulesUnsupported => f.write_str("the platform perimeter has no IPv4 rules"),
            Self::Ipv6RulesUnsupported => f.write_str("the platform perimeter has no IPv6 rules"),
            Self::PortScopingUnsupported => {
                f.write_str("the platform perimeter cannot scope a rule to one port")
            }
            Self::TooManyRules { needed, max } => {
                write!(
                    f,
                    "the profile needs {needed} rules; the platform holds {max}"
                )
            }
            Self::Contradictory(error) | Self::Declaration(error) => fmt::Display::fmt(error, f),
        }
    }
}

impl std::error::Error for PerimeterGap {}

/// A profile's perimeter, compiled and declared (VM §4.4). Its rules permit only what
/// the profile grants; whether they are enforced is a separate CORE-01 fact.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompiledPerimeter {
    network_profile: Digest,
    profile: PerimeterProfile,
    sources: BTreeMap<PerimeterRule, BTreeSet<RuleSource>>,
    host_transport: Vec<HostTransportDecision>,
}

impl CompiledPerimeter {
    /// The digest of the network profile this perimeter was compiled from.
    pub const fn network_profile(&self) -> Digest {
        self.network_profile
    }

    /// The declared V02 perimeter profile.
    pub fn profile(&self) -> &PerimeterProfile {
        &self.profile
    }

    /// The declared rules, sorted.
    pub fn rules(&self) -> &[PerimeterRule] {
        self.profile.rules()
    }

    /// The profile entries each rule came from.
    pub fn sources(&self) -> &BTreeMap<PerimeterRule, BTreeSet<RuleSource>> {
        &self.sources
    }

    /// Decisions the perimeter never sees.
    pub fn host_transport_decisions(&self) -> &[HostTransportDecision] {
        &self.host_transport
    }

    /// The declared rules' verdict for `address:port`: permitted when an allow rule
    /// covers it and no block rule does (blocks win, as on Windows; the rule set has no
    /// overlap anyway). This reads the declaration; it observes nothing.
    pub fn permits(&self, address: IpAddr, port: DestinationPort) -> bool {
        let covered = |action: RuleAction| {
            self.rules()
                .iter()
                .any(|rule| rule.action == action && rule.covers(address, port))
        };
        covered(RuleAction::Allow) && !covered(RuleAction::Block)
    }

    /// The V01 launch perimeter for this profile on `target`: V01 requires a fresh
    /// CORE-01 host probe per block rule before the independent-perimeter predicate holds.
    pub fn launch_perimeter(
        &self,
        target: PerimeterTarget,
        configuration: ConfigurationFingerprint,
    ) -> LaunchPerimeter {
        LaunchPerimeter {
            target,
            profile: self.profile.clone(),
            configuration,
        }
    }
}

fn allow(prefix: IpPrefix, port: DestinationPort) -> PerimeterRule {
    PerimeterRule {
        action: RuleAction::Allow,
        prefix,
        ports: PortSelector::Only(port),
    }
}

fn block(prefix: IpPrefix) -> PerimeterRule {
    PerimeterRule {
        action: RuleAction::Block,
        prefix,
        ports: PortSelector::All,
    }
}

/// Compiles `profile` for the platform perimeter, against the host's own addresses and
/// the sandbox pool. Every gap is listed; with any gap there is no compiled perimeter and
/// the profile's perimeter claim fails.
pub fn compile_perimeter(
    profile: &NetworkProfile,
    pool: &SandboxAddressPool,
    host: &HostAddressState,
    base: PerimeterBase,
    capabilities: PerimeterCapabilities,
) -> Result<CompiledPerimeter, Vec<PerimeterGap>> {
    let mut gaps = Vec::new();
    let mut sources: BTreeMap<PerimeterRule, BTreeSet<RuleSource>> = BTreeMap::new();
    let mut add = |rule: PerimeterRule, source: RuleSource| {
        sources.entry(rule).or_default().insert(source);
    };
    for grant in profile.egress() {
        match &grant.target {
            EgressTarget::Endpoint { address, .. } => add(
                allow(IpPrefix::host(*address), grant.port),
                RuleSource::Endpoint {
                    route: grant.id.clone(),
                },
            ),
            EgressTarget::ExactName { .. } => {
                if grant.perimeter_prefixes.is_empty() {
                    gaps.push(PerimeterGap::NameGrantWithoutPerimeterPrefixes {
                        route: grant.id.clone(),
                    });
                }
                for prefix in &grant.perimeter_prefixes {
                    add(
                        allow(*prefix, grant.port),
                        RuleSource::PerimeterPrefix {
                            route: grant.id.clone(),
                        },
                    );
                }
            }
        }
    }
    for resolver in &profile.document().resolvers {
        for upstream in &resolver.upstream {
            add(
                allow(IpPrefix::host(upstream.address), upstream.port),
                RuleSource::ResolverUpstream {
                    resolver: resolver.id.clone(),
                },
            );
        }
    }
    for address in METADATA_IPV4
        .iter()
        .map(|address| IpAddr::V4(*address))
        .chain(METADATA_IPV6.iter().map(|address| IpAddr::V6(*address)))
    {
        add(block(IpPrefix::host(address)), RuleSource::Metadata);
    }
    for owned in host.owned() {
        add(block(*owned), RuleSource::HostOwned);
    }
    for prefix in pool.prefixes() {
        add(block(prefix), RuleSource::SandboxPool);
    }

    let rules: Vec<PerimeterRule> = sources.keys().copied().collect();
    if !capabilities.ipv4_rules && rules.iter().any(|rule| rule.prefix.network().is_ipv4()) {
        gaps.push(PerimeterGap::Ipv4RulesUnsupported);
    }
    if !capabilities.ipv6_rules && rules.iter().any(|rule| rule.prefix.network().is_ipv6()) {
        gaps.push(PerimeterGap::Ipv6RulesUnsupported);
    }
    if !capabilities.port_scoped_rules
        && rules
            .iter()
            .any(|rule| matches!(rule.ports, PortSelector::Only(_)))
    {
        gaps.push(PerimeterGap::PortScopingUnsupported);
    }
    if rules.len() > usize::try_from(capabilities.max_rules).unwrap_or(usize::MAX) {
        gaps.push(PerimeterGap::TooManyRules {
            needed: rules.len(),
            max: capabilities.max_rules,
        });
    }
    if let Err(error) = check_rules(&rules) {
        gaps.push(PerimeterGap::Contradictory(error));
    }
    if !gaps.is_empty() {
        return Err(gaps);
    }
    let declared = PerimeterProfile::declare(
        base.platform,
        base.options,
        base.declared,
        base.remote,
        base.broker_identity,
        rules,
    )
    .map_err(|error| vec![PerimeterGap::Declaration(error)])?;

    let document = profile.document();
    let mut host_transport = vec![HostTransportDecision::GatewayListeners];
    host_transport.extend(document.ingress.iter().map(|entry| {
        HostTransportDecision::Publication {
            service: entry.service.clone(),
            port: entry.port,
        }
    }));
    host_transport.extend(
        document
            .links
            .iter()
            .map(|link| HostTransportDecision::SandboxLink {
                direction: link.direction,
                service: link.service.clone(),
                port: link.port,
            }),
    );
    Ok(CompiledPerimeter {
        network_profile: profile.digest(),
        profile: declared,
        sources,
        host_transport,
    })
}
