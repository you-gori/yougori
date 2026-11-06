//! The independent perimeter as a declared profile record (VM §4.4; VM-W15; VM-P11,
//! VM-P26, VM-P27). Nothing here installs, changes or probes a rule: the record states
//! what each platform's perimeter must provide and how its rules are expressed.
//!
//! Whether a rule is enforced is a CORE-01 fact only: a fresh host-probe `Satisfied` for
//! `Capability::PerimeterRuleEnforced` on exactly that rule's `PerimeterRuleSubject`
//! (machine, perimeter, rule, principal), evaluated by the `ProbeRegistry`
//! ([`RuleEnforced`]). Missing, stale, guest-reported, inconclusive or other-subject
//! evidence refuses with CORE-01's [`EvidenceRefusal`]. A [`MustProbe`] is the raw record
//! of the line-1989 procedure; it maps to the observation a registered host adapter
//! reports and decides nothing by itself.

use std::collections::BTreeSet;
use std::fmt;
use std::net::IpAddr;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::address::IpPrefix;
use super::name::DestinationPort;
use crate::foundation::coordination::PerimeterId;
use crate::foundation::evidence::{
    Capability, ConfigurationFingerprint, EvidenceRefusal, Observation, PerimeterRuleSubject,
    ProbeRegistry, Requirement, Satisfied, Subject, SupportDetail, UnknownReason,
    UnsupportedReason,
};
use crate::foundation::ids::{Clock, Digest, DigestBuilder, MonotonicTime};

/// The platform a perimeter runs on (VM §4.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PerimeterPlatform {
    Linux,
    Windows,
    MacOs,
    Remote,
}

/// A property a perimeter must provide (VM §4.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PerimeterProperty {
    /// Rules are installed and updated transactionally (line 1987).
    TransactionalInstall,
    /// The installed rules' scope is verified (line 1987).
    ScopeVerified,
    /// Unrelated rules are preserved (line 1987).
    UnrelatedRulesPreserved,
    /// A rollback exists (line 1987).
    RollbackAvailable,
    /// Elevation is used only for the concrete operations that need it (line 1987).
    ElevationOnlyForConcreteOperations,
    /// Linux: dedicated identities or network namespaces, or equivalent isolation.
    DedicatedIdentityOrNetNamespace,
    /// Linux: narrowly scoped nftables rules.
    NarrowNftablesRules,
    /// Linux: resource limits.
    ResourceLimits,
    /// Linux: an empty hypervisor network namespace still permits only the required
    /// local IPC.
    EmptyNamespaceOnlyRequiredIpc,
    /// Linux: rootless namespace and cgroup delegation was tested, not assumed.
    RootlessDelegationTested,
    /// Windows: WFP/firewall scope is validated against the actual process or service
    /// identity.
    ScopedToBrokerIdentity,
    /// Windows: the enabled network profiles were validated.
    EnabledNetworkProfilesValidated,
    /// Windows: explicit block rules take precedence over conflicting allows, and the
    /// rule set does not rely on "block all, then allow".
    BlockPrecedenceAccounted,
    /// Windows: the whole PC's outbound defaults are not changed.
    MachineOutboundDefaultsUnchanged,
    /// macOS: the exact supported enforcement API and identities were verified.
    SupportedEnforcementApiVerified,
    /// macOS: the rule is scoped to the process, since a user-ID rule cannot single out
    /// one same-user process (VM-P27).
    ProcessScopedNotUserScoped,
    /// macOS: no deprecated or private sandbox interface is presented as supported.
    NoDeprecatedOrPrivateInterface,
    /// Remote: the perimeter is outside the guest.
    PerimeterOutsideGuest,
    /// Remote: the perimeter is independent of the provider operator, required when the
    /// profile protects against that operator.
    IndependentOfProviderOperator,
}

/// Choices that change which properties a platform requires.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PerimeterOptions {
    /// Linux: the perimeter relies on rootless namespace or cgroup delegation.
    pub rootless_delegation: bool,
    /// Remote: the profile protects against a malicious provider operator.
    pub protects_against_provider_operator: bool,
}

impl PerimeterPlatform {
    /// The properties every perimeter on this platform must provide (VM §4.4).
    pub fn required_properties(self, options: PerimeterOptions) -> BTreeSet<PerimeterProperty> {
        use PerimeterProperty as P;
        let mut required: BTreeSet<P> = [
            P::TransactionalInstall,
            P::ScopeVerified,
            P::UnrelatedRulesPreserved,
            P::RollbackAvailable,
            P::ElevationOnlyForConcreteOperations,
        ]
        .into_iter()
        .collect();
        let specific: &[P] = match self {
            Self::Linux => &[
                P::DedicatedIdentityOrNetNamespace,
                P::NarrowNftablesRules,
                P::ResourceLimits,
                P::EmptyNamespaceOnlyRequiredIpc,
            ],
            Self::Windows => &[
                P::ScopedToBrokerIdentity,
                P::EnabledNetworkProfilesValidated,
                P::BlockPrecedenceAccounted,
                P::MachineOutboundDefaultsUnchanged,
            ],
            Self::MacOs => &[
                P::SupportedEnforcementApiVerified,
                P::ProcessScopedNotUserScoped,
                P::NoDeprecatedOrPrivateInterface,
            ],
            Self::Remote => &[P::PerimeterOutsideGuest],
        };
        required.extend(specific.iter().copied());
        if self == Self::Linux && options.rootless_delegation {
            required.insert(P::RootlessDelegationTested);
        }
        if self == Self::Remote && options.protects_against_provider_operator {
            required.insert(P::IndependentOfProviderOperator);
        }
        required
    }
}

/// Where a remote perimeter is enforced (VM §4.4, Remote).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RemoteEnforcement {
    /// A host perimeter outside the guest, run by the provider's infrastructure.
    HostOutsideGuest,
    /// The provider operator's own firewall.
    ProviderOperatorFirewall,
    /// A network control the provider operator does not run.
    IndependentNetworkControl,
}

/// Which ports a rule covers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PortSelector {
    All,
    Only(DestinationPort),
}

impl PortSelector {
    fn overlaps(self, other: Self) -> bool {
        match (self, other) {
            (Self::Only(left), Self::Only(right)) => left == right,
            _ => true,
        }
    }
}

/// Whether a rule allows or blocks.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleAction {
    Allow,
    Block,
}

/// One declared perimeter rule. Default deny is implicit; rules are never installed by
/// this module.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PerimeterRule {
    pub action: RuleAction,
    pub prefix: IpPrefix,
    pub ports: PortSelector,
}

impl PerimeterRule {
    /// The digest domain of [`PerimeterRule::digest`].
    pub const DIGEST_DOMAIN: &'static str = "yougori/sandbox/perimeter-rule/v1";

    /// The digest that names this rule in a CORE-01 [`PerimeterRuleSubject`] and in a
    /// host's block record ([`ProbeOutcome::BlockedByRule`]).
    pub fn digest(&self) -> Digest {
        DigestBuilder::new(Self::DIGEST_DOMAIN)
            .str(&format!(
                "{:?}|{}|{:?}",
                self.action, self.prefix, self.ports
            ))
            .finish()
    }

    /// True when the rule's prefix and ports cover `address:port`.
    pub fn covers(&self, address: IpAddr, port: DestinationPort) -> bool {
        self.prefix.contains(address) && self.ports.overlaps(PortSelector::Only(port))
    }

    fn overlaps(&self, other: &PerimeterRule) -> bool {
        self.prefix.overlaps(&other.prefix) && self.ports.overlaps(other.ports)
    }
}

/// Why a perimeter profile or enforcement context was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PerimeterError {
    /// A platform property is not declared.
    MissingProperty { property: PerimeterProperty },
    /// A block rule overlaps an allow rule. Explicit blocks win on Windows, and "block
    /// all, then allow" is not a portable ordering recipe (line 1983), so the set is
    /// contradictory on every platform.
    ContradictoryRules {
        block: PerimeterRule,
        allow: PerimeterRule,
    },
    /// A remote profile names no enforcement point, or a local profile names one.
    RemoteEnforcementMismatch,
    /// The provider operator's firewall is not an independent control against that
    /// operator (line 1985).
    OperatorFirewallNotIndependent,
    /// An endpoint's enforcement context permits something other than that one
    /// destination (line 1958).
    ContextNotDedicated { endpoint: (IpAddr, DestinationPort) },
}

impl fmt::Display for PerimeterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingProperty { property } => {
                write!(f, "the perimeter profile does not declare {property:?}")
            }
            Self::ContradictoryRules { block, allow } => write!(
                f,
                "block rule for {} overlaps allow rule for {}; a block-all rule with a \
                 contradictory exception cannot express this, so permit only the destination",
                block.prefix, allow.prefix
            ),
            Self::RemoteEnforcementMismatch => f.write_str(
                "a remote perimeter must name where it is enforced, and a local one must not",
            ),
            Self::OperatorFirewallNotIndependent => f.write_str(
                "the provider operator's own firewall is not independent of that operator",
            ),
            Self::ContextNotDedicated { endpoint } => write!(
                f,
                "the enforcement context for {}:{} must permit only that destination",
                endpoint.0, endpoint.1
            ),
        }
    }
}

impl std::error::Error for PerimeterError {}

/// Refuses any block rule that overlaps an allow rule.
pub fn check_rules(rules: &[PerimeterRule]) -> Result<(), PerimeterError> {
    for block in rules.iter().filter(|rule| rule.action == RuleAction::Block) {
        if let Some(allow) = rules
            .iter()
            .find(|rule| rule.action == RuleAction::Allow && rule.overlaps(block))
        {
            return Err(PerimeterError::ContradictoryRules {
                block: *block,
                allow: *allow,
            });
        }
    }
    Ok(())
}

/// A declared perimeter profile (VM §4.4): its platform, the properties it declares,
/// where a remote perimeter is enforced, the identity of the broker it constrains and its
/// rules. Declaring a profile installs nothing.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "RawProfile", into = "RawProfile")]
pub struct PerimeterProfile {
    platform: PerimeterPlatform,
    options: PerimeterOptions,
    declared: BTreeSet<PerimeterProperty>,
    remote: Option<RemoteEnforcement>,
    broker_identity: Digest,
    rules: Vec<PerimeterRule>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawProfile {
    platform: PerimeterPlatform,
    options: PerimeterOptions,
    declared: BTreeSet<PerimeterProperty>,
    remote: Option<RemoteEnforcement>,
    broker_identity: Digest,
    rules: Vec<PerimeterRule>,
}

impl TryFrom<RawProfile> for PerimeterProfile {
    type Error = PerimeterError;

    fn try_from(raw: RawProfile) -> Result<Self, Self::Error> {
        Self::declare(
            raw.platform,
            raw.options,
            raw.declared,
            raw.remote,
            raw.broker_identity,
            raw.rules,
        )
    }
}

impl From<PerimeterProfile> for RawProfile {
    fn from(profile: PerimeterProfile) -> Self {
        Self {
            platform: profile.platform,
            options: profile.options,
            declared: profile.declared,
            remote: profile.remote,
            broker_identity: profile.broker_identity,
            rules: profile.rules,
        }
    }
}

impl PerimeterProfile {
    /// The digest domain of [`PerimeterProfile::digest`].
    pub const DIGEST_DOMAIN: &'static str = "yougori/sandbox/perimeter-profile/v1";

    /// What a perimeter cannot do, whatever its profile (line 1980).
    pub const LIMITS: [&'static str; 2] = [
        "it cannot enforce provider method or path semantics inside encrypted traffic",
        "it cannot make an allowed public destination harmless",
    ];

    /// Declares a profile, refusing a missing platform property, a contradictory rule
    /// set, a remote profile without an enforcement point (or a local one with one), and
    /// an operator firewall offered as independent of that operator.
    pub fn declare(
        platform: PerimeterPlatform,
        options: PerimeterOptions,
        declared: BTreeSet<PerimeterProperty>,
        remote: Option<RemoteEnforcement>,
        broker_identity: Digest,
        rules: Vec<PerimeterRule>,
    ) -> Result<Self, PerimeterError> {
        if let Some(property) = platform
            .required_properties(options)
            .into_iter()
            .find(|property| !declared.contains(property))
        {
            return Err(PerimeterError::MissingProperty { property });
        }
        match (platform, remote) {
            (PerimeterPlatform::Remote, None) => {
                return Err(PerimeterError::RemoteEnforcementMismatch)
            }
            (PerimeterPlatform::Remote, Some(RemoteEnforcement::ProviderOperatorFirewall))
                if options.protects_against_provider_operator =>
            {
                return Err(PerimeterError::OperatorFirewallNotIndependent)
            }
            (PerimeterPlatform::Remote, Some(_)) => {}
            (_, Some(_)) => return Err(PerimeterError::RemoteEnforcementMismatch),
            (_, None) => {}
        }
        check_rules(&rules)?;
        Ok(Self {
            platform,
            options,
            declared,
            remote,
            broker_identity,
            rules,
        })
    }

    pub const fn platform(&self) -> PerimeterPlatform {
        self.platform
    }

    pub fn declared(&self) -> &BTreeSet<PerimeterProperty> {
        &self.declared
    }

    pub const fn broker_identity(&self) -> Digest {
        self.broker_identity
    }

    pub fn rules(&self) -> &[PerimeterRule] {
        &self.rules
    }

    /// A stable digest of the whole profile.
    pub fn digest(&self) -> Digest {
        let mut builder = DigestBuilder::new(Self::DIGEST_DOMAIN)
            .str(&format!("{:?}", self.platform))
            .u64(u64::from(self.options.rootless_delegation))
            .u64(u64::from(self.options.protects_against_provider_operator))
            .str(&format!("{:?}", self.remote))
            .digest(&self.broker_identity)
            .u64(self.declared.len() as u64);
        for property in &self.declared {
            builder = builder.str(&format!("{property:?}"));
        }
        builder = builder.u64(self.rules.len() as u64);
        for rule in &self.rules {
            builder = builder.str(&format!(
                "{:?}|{}|{:?}",
                rule.action, rule.prefix, rule.ports
            ));
        }
        builder.finish()
    }

    /// The CORE-01 subject of each block rule of this profile on `target`, for this
    /// profile's broker identity: the principal the rule restricts and the must-probe
    /// runs as (line 1989).
    pub fn block_rule_subjects(
        &self,
        target: PerimeterTarget,
    ) -> Vec<(PerimeterRule, PerimeterRuleSubject)> {
        self.rules
            .iter()
            .filter(|rule| rule.action == RuleAction::Block)
            .map(|rule| (*rule, target.subject(rule.digest(), self.broker_identity)))
            .collect()
    }

    /// One host-only CORE-01 requirement for [`Capability::PerimeterRuleEnforced`] per
    /// block rule of this profile on `target`.
    pub fn requirements(
        &self,
        target: PerimeterTarget,
        max_age: Duration,
        configuration: ConfigurationFingerprint,
    ) -> Vec<(PerimeterRule, Requirement)> {
        self.block_rule_subjects(target)
            .into_iter()
            .map(|(rule, subject)| {
                (
                    rule,
                    RuleEnforced::requirement(subject, max_age, configuration),
                )
            })
            .collect()
    }

    /// Judges every block rule of this profile on `target` through `registry` at its
    /// current time. A rule counts only with a fresh host-probe [`Satisfied`] for its own
    /// subject; every other rule is listed with CORE-01's refusal.
    pub fn assess<C: Clock>(
        &self,
        registry: &ProbeRegistry<C>,
        target: PerimeterTarget,
        max_age: Duration,
        configuration: ConfigurationFingerprint,
    ) -> PerimeterAssessment {
        let mut assessment = PerimeterAssessment::default();
        for (rule, subject) in self.block_rule_subjects(target) {
            match RuleEnforced::evaluate(registry, subject, max_age, configuration) {
                Ok(enforced) => assessment.enforced.push((rule, enforced)),
                Err(refusal) => assessment.refused.push((rule, refusal)),
            }
        }
        assessment
    }
}

/// Where a perimeter is installed: the machine and the perimeter the host prepared for
/// the boot (VM §6.1 perimeter_ready).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PerimeterTarget {
    /// Digest of the machine's stable identity.
    pub machine: Digest,
    pub perimeter: PerimeterId,
}

impl PerimeterTarget {
    /// The CORE-01 subject of the rule named `rule` on this target, restricting
    /// `principal`.
    pub fn subject(&self, rule: Digest, principal: Digest) -> PerimeterRuleSubject {
        PerimeterRuleSubject {
            machine: self.machine,
            perimeter: self.perimeter.digest(),
            rule,
            principal,
        }
    }
}

/// A profile's block rules as CORE-01 judged them at one moment.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PerimeterAssessment {
    pub enforced: Vec<(PerimeterRule, RuleEnforced)>,
    /// Rules CORE-01 refused: missing, guest-reported, stale, under a changed
    /// configuration, not enforced or inconclusive. Inconclusive never counts as enforced.
    pub refused: Vec<(PerimeterRule, EvidenceRefusal)>,
}

impl PerimeterAssessment {
    /// True only when the profile has a block rule and every block rule was shown
    /// enforced; a profile without block rules shows nothing.
    pub fn verified(&self) -> bool {
        self.refused.is_empty() && !self.enforced.is_empty()
    }

    /// When the first enforced fact stops being fresh, on the registry's clock.
    pub fn fresh_until(&self) -> Option<MonotonicTime> {
        self.enforced
            .iter()
            .map(|(_, enforced)| enforced.evidence().fresh_until())
            .min()
    }
}

/// The fact that one perimeter rule is enforced (line 1989; VM-W15; VM-P26): a thin view
/// over a fresh CORE-01 [`Satisfied`] for [`Capability::PerimeterRuleEnforced`] on exactly
/// one [`PerimeterRuleSubject`]. Only [`RuleEnforced::evaluate`] makes one, from a
/// host-only requirement evaluated by a [`ProbeRegistry`]; its freshness is the
/// evidence's, on that registry's clock.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuleEnforced {
    subject: PerimeterRuleSubject,
    evidence: Satisfied,
}

impl RuleEnforced {
    /// The host-only requirement for `subject`: only a host probe satisfies it, never a
    /// guest report (CORE-01; VM-W09).
    pub fn requirement(
        subject: PerimeterRuleSubject,
        max_age: Duration,
        configuration: ConfigurationFingerprint,
    ) -> Requirement {
        Requirement::host_only(
            Capability::PerimeterRuleEnforced,
            Subject::PerimeterRule(subject),
            max_age,
            configuration,
        )
    }

    /// Evaluates the requirement for `subject` in `registry` at its current time, or
    /// returns CORE-01's refusal. Evidence about another machine, perimeter, rule or
    /// principal never counts.
    pub fn evaluate<C: Clock>(
        registry: &ProbeRegistry<C>,
        subject: PerimeterRuleSubject,
        max_age: Duration,
        configuration: ConfigurationFingerprint,
    ) -> Result<Self, EvidenceRefusal> {
        let requirement = Self::requirement(subject, max_age, configuration);
        let evidence = registry.evaluate(&requirement)?;
        // CORE-01 already matches by subject identity; the recheck keeps that invariant
        // local, so no other subject can stand in for this one.
        if evidence.capability() != Capability::PerimeterRuleEnforced
            || evidence.subject() != requirement.subject.identity()
            || *evidence.detail() != SupportDetail::PerimeterRuleEnforced
        {
            return Err(EvidenceRefusal::Missing {
                capability: Capability::PerimeterRuleEnforced,
            });
        }
        Ok(Self { subject, evidence })
    }

    pub fn subject(&self) -> &PerimeterRuleSubject {
        &self.subject
    }

    /// The CORE-01 evidence this fact is a view of.
    pub fn evidence(&self) -> &Satisfied {
        &self.evidence
    }
}

/// What one probe connection observed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeOutcome {
    Connected,
    /// The connection was refused and the host recorded which rule did it.
    BlockedByRule {
        rule: Digest,
    },
    /// Refused or dropped with no evidence of which rule acted.
    FailedWithoutEvidence,
    TimedOut,
    Unreachable,
}

/// The raw record of a must-probe (line 1989): a controlled endpoint known to be
/// reachable without the tested rule, probed as the actual broker identity, with
/// evidence of the intended block. It becomes evidence only as the observation of a host
/// probe adapter registered in a [`ProbeRegistry`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MustProbe {
    pub address: IpAddr,
    pub port: DestinationPort,
    /// True when the endpoint is one the test controls, not an arbitrary or unused one.
    pub controlled_endpoint: bool,
    /// The digest of the rule under test.
    pub rule: Digest,
    /// The identity both probe runs used.
    pub probing_identity: Digest,
    /// The positive control: the same probe without the tested rule.
    pub without_rule: ProbeOutcome,
    /// The probe with the rule in place.
    pub with_rule: ProbeOutcome,
}

impl MustProbe {
    /// The observation a host must-probe adapter reports for a block rule's `subject`.
    /// Only a reached positive control on a controlled endpoint inside the rule, run as
    /// the subject's principal, plus a block recorded for that rule is
    /// [`SupportDetail::PerimeterRuleEnforced`]; a connection with the rule in place is
    /// unsupported (not enforced); a timeout, an unreachable or uncontrolled target and a
    /// silent failure are unknown, which never passes (VM-P26).
    pub fn observe_block_rule(
        &self,
        rule: &PerimeterRule,
        subject: &PerimeterRuleSubject,
        configuration: ConfigurationFingerprint,
        fresh_for: Duration,
    ) -> Observation {
        let in_scope = rule.action == RuleAction::Block
            && subject.rule == rule.digest()
            && rule.covers(self.address, self.port);
        self.observation(in_scope, subject, configuration, fresh_for)
    }

    /// The observation for an enforcement context's default deny: the probe must target
    /// a destination the context does not permit.
    pub fn observe_default_deny(
        &self,
        context: &EnforcementContext,
        subject: &PerimeterRuleSubject,
        configuration: ConfigurationFingerprint,
        fresh_for: Duration,
    ) -> Observation {
        let in_scope = subject.rule == context.default_deny_digest()
            && subject.perimeter == context.perimeter.digest()
            && !context.permits(self.address, self.port);
        self.observation(in_scope, subject, configuration, fresh_for)
    }

    fn observation(
        &self,
        in_scope: bool,
        subject: &PerimeterRuleSubject,
        configuration: ConfigurationFingerprint,
        fresh_for: Duration,
    ) -> Observation {
        let unknown = |reason| Observation::unknown(configuration, fresh_for, reason);
        if !in_scope || self.rule != subject.rule || self.probing_identity != subject.principal {
            return unknown(UnknownReason::InconsistentReport);
        }
        if !self.controlled_endpoint || self.without_rule != ProbeOutcome::Connected {
            return unknown(UnknownReason::Inconclusive);
        }
        match self.with_rule {
            ProbeOutcome::Connected => {
                Observation::unsupported(configuration, fresh_for, UnsupportedReason::NotEnforced)
            }
            ProbeOutcome::BlockedByRule { rule } if rule == subject.rule => Observation::supported(
                configuration,
                fresh_for,
                SupportDetail::PerimeterRuleEnforced,
            ),
            ProbeOutcome::BlockedByRule { .. } => unknown(UnknownReason::InconsistentReport),
            ProbeOutcome::FailedWithoutEvidence | ProbeOutcome::TimedOut => {
                unknown(UnknownReason::Inconclusive)
            }
            ProbeOutcome::Unreachable => unknown(UnknownReason::Unreachable),
        }
    }
}

/// The enforcement context of an exact endpoint grant (line 1958): a perimeter whose rules
/// permit only that one destination. Default deny is implicit, so no block rule is needed
/// and none may overlap the endpoint.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnforcementContext {
    pub perimeter: PerimeterId,
    pub rules: Vec<PerimeterRule>,
}

impl EnforcementContext {
    /// A context permitting exactly `address:port`.
    pub fn dedicated(perimeter: PerimeterId, address: IpAddr, port: DestinationPort) -> Self {
        Self {
            perimeter,
            rules: vec![PerimeterRule {
                action: RuleAction::Allow,
                prefix: IpPrefix::host(address),
                ports: PortSelector::Only(port),
            }],
        }
    }

    /// Refuses a context that permits anything besides `address:port`, or that pairs a
    /// broad block with an exception for it.
    pub fn check_dedicated(
        &self,
        address: IpAddr,
        port: DestinationPort,
    ) -> Result<(), PerimeterError> {
        check_rules(&self.rules)?;
        let only = PerimeterRule {
            action: RuleAction::Allow,
            prefix: IpPrefix::host(address),
            ports: PortSelector::Only(port),
        };
        let allows: Vec<&PerimeterRule> = self
            .rules
            .iter()
            .filter(|rule| rule.action == RuleAction::Allow)
            .collect();
        match allows.as_slice() {
            [single] if **single == only => Ok(()),
            _ => Err(PerimeterError::ContextNotDedicated {
                endpoint: (address, port),
            }),
        }
    }

    /// The digest domain of [`EnforcementContext::default_deny_digest`].
    pub const DEFAULT_DENY_DOMAIN: &'static str = "yougori/sandbox/perimeter-default-deny/v1";

    /// Names this context's default deny, everything its allow rules do not permit, as
    /// the rule a must-probe of the context tests.
    pub fn default_deny_digest(&self) -> Digest {
        let mut builder = DigestBuilder::new(Self::DEFAULT_DENY_DOMAIN)
            .digest(&self.perimeter.digest())
            .u64(self.rules.len() as u64);
        for rule in &self.rules {
            builder = builder.digest(&rule.digest());
        }
        builder.finish()
    }

    /// True when an allow rule covers `address:port`.
    pub fn permits(&self, address: IpAddr, port: DestinationPort) -> bool {
        self.rules
            .iter()
            .any(|rule| rule.action == RuleAction::Allow && rule.covers(address, port))
    }

    /// The CORE-01 subject of this context's default deny on `machine`, restricting
    /// `principal`.
    pub fn default_deny_subject(&self, machine: Digest, principal: Digest) -> PerimeterRuleSubject {
        PerimeterTarget {
            machine,
            perimeter: self.perimeter,
        }
        .subject(self.default_deny_digest(), principal)
    }

    /// The context's "rule enforced" fact (line 1958): a fresh host-probe CORE-01
    /// [`Satisfied`] for its default deny on `machine` for `principal`, or CORE-01's
    /// refusal.
    pub fn enforced<C: Clock>(
        &self,
        registry: &ProbeRegistry<C>,
        machine: Digest,
        principal: Digest,
        max_age: Duration,
        configuration: ConfigurationFingerprint,
    ) -> Result<RuleEnforced, EvidenceRefusal> {
        RuleEnforced::evaluate(
            registry,
            self.default_deny_subject(machine, principal),
            max_age,
            configuration,
        )
    }
}
