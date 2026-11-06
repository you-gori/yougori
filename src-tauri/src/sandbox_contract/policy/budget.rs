//! Budgets and how they compose (VM part §2.4 line 1802): minima are taken only where two
//! budgets describe the same resource and accounting scope. Budgets of different scopes
//! are separate limits and all apply.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use super::tuple::ResourceRef;
use crate::foundation::transfer::VM_D12_GENERAL_RELEASE_BUDGET_BYTES;

/// VM-D12's starting idle lifetime: 12 hours.
pub const VM_D12_IDLE_LIFETIME_SECONDS: u64 = 12 * 60 * 60;
/// VM-D12's starting absolute lifetime of a task sandbox: 24 hours.
pub const VM_D12_TASK_ABSOLUTE_LIFETIME_SECONDS: u64 = 24 * 60 * 60;
/// VM-D12's starting service renewal period: 7 days.
pub const VM_D12_SERVICE_RENEWAL_SECONDS: u64 = 7 * 24 * 60 * 60;

/// What a budget limits. The unit is part of the resource, so two budgets of one
/// resource never differ in unit.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BudgetResource {
    /// Bytes leaving the sandbox through any outbound channel (§2.2 release bound).
    ReleaseBytes,
    /// External effects: releases and provider operations (§2.2 release bound).
    ReleaseEffects,
    /// Idle lifetime before the sandbox ends (VM-D12).
    IdleLifetimeSeconds,
    /// Absolute lifetime of a task sandbox (VM-D12).
    AbsoluteLifetimeSeconds,
    /// Renewal period of a service sandbox lease (VM-D12).
    ServiceRenewalSeconds,
    /// Effects delegated to the guest through short-lived external capabilities (§4.5:
    /// "scope, audience, expiry and delegated budget explicit; still a credential"). Each
    /// delivery of a short-lived credential is charged the number of external effects the
    /// minted credential may authorize, so the total authority handed into the guest this
    /// way is bounded. Listed last so earlier resources keep their storage order.
    ShortLivedCredentialEffects,
}

/// The unit of a [`BudgetResource`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BudgetUnit {
    Bytes,
    Effects,
    Seconds,
}

impl BudgetResource {
    pub const ALL: [Self; 6] = [
        Self::ReleaseBytes,
        Self::ReleaseEffects,
        Self::IdleLifetimeSeconds,
        Self::AbsoluteLifetimeSeconds,
        Self::ServiceRenewalSeconds,
        Self::ShortLivedCredentialEffects,
    ];

    pub const fn unit(self) -> BudgetUnit {
        match self {
            Self::ReleaseBytes => BudgetUnit::Bytes,
            Self::ReleaseEffects | Self::ShortLivedCredentialEffects => BudgetUnit::Effects,
            Self::IdleLifetimeSeconds
            | Self::AbsoluteLifetimeSeconds
            | Self::ServiceRenewalSeconds => BudgetUnit::Seconds,
        }
    }

    /// Whether requests spend it. Lifetimes are enforced by coordination leases (CORE-04),
    /// not charged per request.
    pub const fn is_spent_per_request(self) -> bool {
        matches!(
            self,
            Self::ReleaseBytes | Self::ReleaseEffects | Self::ShortLivedCredentialEffects
        )
    }

    /// The stable tag in canonical encodings.
    pub const fn tag(self) -> &'static str {
        match self {
            Self::ReleaseBytes => "release_bytes",
            Self::ReleaseEffects => "release_effects",
            Self::IdleLifetimeSeconds => "idle_lifetime_seconds",
            Self::AbsoluteLifetimeSeconds => "absolute_lifetime_seconds",
            Self::ServiceRenewalSeconds => "service_renewal_seconds",
            Self::ShortLivedCredentialEffects => "short_lived_credential_effects",
        }
    }
}

impl fmt::Display for BudgetResource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::ReleaseBytes => "released bytes",
            Self::ReleaseEffects => "external effects",
            Self::IdleLifetimeSeconds => "idle lifetime in seconds",
            Self::AbsoluteLifetimeSeconds => "absolute lifetime in seconds",
            Self::ServiceRenewalSeconds => "service renewal period in seconds",
            Self::ShortLivedCredentialEffects => {
                "effects delegated through short-lived credentials"
            }
        })
    }
}

strict_policy_enum! {
    /// What a budget is accounted over (VM-W03: budget scope explicit).
    #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub enum AccountingScope tag "scope" {
        /// One authorization generation of the sandbox (§2.2: "per generation"); a new
        /// activation starts at zero.
        Generation,
        /// The whole execution, across its generations; spending carries over.
        Execution,
        /// The whole tenant; the caller aggregates spending across executions.
        Tenant,
        /// One channel within one generation, such as a single route.
        Channel { resource: ResourceRef },
    }
}

impl AccountingScope {
    /// Whether a request on `resource` is accounted in this scope.
    pub fn applies_to(&self, resource: &ResourceRef) -> bool {
        match self {
            Self::Generation | Self::Execution | Self::Tenant => true,
            Self::Channel { resource: channel } => channel == resource,
        }
    }

    /// Whether spending in this scope outlives one activation.
    pub fn carries_over(&self) -> bool {
        matches!(self, Self::Execution | Self::Tenant)
    }

    /// The stable tag in canonical encodings.
    pub fn tag(&self) -> &'static str {
        match self {
            Self::Generation => "generation",
            Self::Execution => "execution",
            Self::Tenant => "tenant",
            Self::Channel { .. } => "channel",
        }
    }
}

impl fmt::Display for AccountingScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Generation => f.write_str("per generation"),
            Self::Execution => f.write_str("per execution"),
            Self::Tenant => f.write_str("per tenant"),
            Self::Channel { resource } => write!(f, "on {resource} per generation"),
        }
    }
}

/// A resource in one accounting scope: the only thing two budgets must share before
/// their minimum is meaningful.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BudgetKey {
    pub resource: BudgetResource,
    pub scope: AccountingScope,
}

impl fmt::Display for BudgetKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.resource, self.scope)
    }
}

/// One budget; `limit` is in the resource's unit ([`BudgetResource::unit`]).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Budget {
    pub resource: BudgetResource,
    pub scope: AccountingScope,
    pub limit: u64,
}

impl Budget {
    pub fn key(&self) -> BudgetKey {
        BudgetKey {
            resource: self.resource,
            scope: self.scope.clone(),
        }
    }
}

/// One layer listed the same resource and scope twice, so its limit is ambiguous.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DuplicateBudget {
    pub key: BudgetKey,
}

impl fmt::Display for DuplicateBudget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "the budget for {} is listed twice in one layer; list it once",
            self.key
        )
    }
}

impl std::error::Error for DuplicateBudget {}

/// Budgets keyed by resource and accounting scope (VM §2.4 line 1802).
///
/// [`BudgetSet::compose`] takes the minimum of two limits only for the same key; a key
/// present in one layer only keeps that layer's limit, and keys of different scopes are
/// never compared.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "Vec<Budget>", into = "Vec<Budget>")]
pub struct BudgetSet {
    limits: BTreeMap<BudgetKey, u64>,
}

impl BudgetSet {
    /// Refuses a key listed twice.
    pub fn new(budgets: impl IntoIterator<Item = Budget>) -> Result<Self, DuplicateBudget> {
        let mut limits = BTreeMap::new();
        for budget in budgets {
            let key = budget.key();
            if limits.contains_key(&key) {
                return Err(DuplicateBudget { key });
            }
            limits.insert(key, budget.limit);
        }
        Ok(Self { limits })
    }

    /// VM-D12's starting values for a task sandbox: 8 MiB of general release per
    /// generation, 12 hours idle and 24 hours absolute lifetime per execution.
    pub fn vm_d12_task_defaults() -> Self {
        let limits = BTreeMap::from([
            (
                BudgetKey {
                    resource: BudgetResource::ReleaseBytes,
                    scope: AccountingScope::Generation,
                },
                VM_D12_GENERAL_RELEASE_BUDGET_BYTES,
            ),
            (
                BudgetKey {
                    resource: BudgetResource::IdleLifetimeSeconds,
                    scope: AccountingScope::Execution,
                },
                VM_D12_IDLE_LIFETIME_SECONDS,
            ),
            (
                BudgetKey {
                    resource: BudgetResource::AbsoluteLifetimeSeconds,
                    scope: AccountingScope::Execution,
                },
                VM_D12_TASK_ABSOLUTE_LIFETIME_SECONDS,
            ),
        ]);
        Self { limits }
    }

    /// Both layers' budgets: the minimum where they share a key, each layer's own limit
    /// elsewhere.
    pub fn compose(&self, other: &Self) -> Self {
        let mut limits = self.limits.clone();
        for (key, limit) in &other.limits {
            let combined = limits.get(key).map_or(*limit, |mine| (*mine).min(*limit));
            limits.insert(key.clone(), combined);
        }
        Self { limits }
    }

    pub fn limit(&self, key: &BudgetKey) -> Option<u64> {
        self.limits.get(key).copied()
    }

    pub fn contains_resource(&self, resource: BudgetResource) -> bool {
        self.limits.keys().any(|key| key.resource == resource)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&BudgetKey, u64)> {
        self.limits.iter().map(|(key, limit)| (key, *limit))
    }

    pub fn len(&self) -> usize {
        self.limits.len()
    }

    pub fn is_empty(&self) -> bool {
        self.limits.is_empty()
    }
}

impl TryFrom<Vec<Budget>> for BudgetSet {
    type Error = DuplicateBudget;

    fn try_from(budgets: Vec<Budget>) -> Result<Self, Self::Error> {
        Self::new(budgets)
    }
}

impl From<BudgetSet> for Vec<Budget> {
    fn from(set: BudgetSet) -> Self {
        set.limits
            .into_iter()
            .map(|(key, limit)| Budget {
                resource: key.resource,
                scope: key.scope,
                limit,
            })
            .collect()
    }
}
