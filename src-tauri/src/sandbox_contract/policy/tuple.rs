//! Permission tuples and their exact set algebra (VM part §2.4, lines 1789–1795).
//!
//! A permission is a tuple (principal, operation, resource, context, generation). A
//! [`PermissionSet`] denotes the set of concrete tuples it permits. Its one pattern is
//! [`GenerationScope::EveryGeneration`], which denotes the tuple at every authorization
//! epoch; every other field is an exact name, with no wildcards (VM-W03: exact names by
//! default). Intersection and union are exact on those denotations, so
//! `product_ceiling ∩ requested ∩ delegated` is computed without approximation.

use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Deserializer, Serialize};

use super::budget::BudgetResource;
use crate::foundation::ids::{validate_identifier, AuthorizationEpoch, IdError};
use crate::sandbox_contract::destinations::{route_reference, Authority};

macro_rules! policy_name {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        #[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            /// Accepts the shared identifier grammar (`ids::validate_identifier`): 1–128
            /// letters, digits, '.', '_', ':' or '-', starting with a letter or digit.
            pub fn new(value: impl Into<String>) -> Result<Self, IdError> {
                let value = value.into();
                validate_identifier(&value)?;
                Ok(Self(value))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}({})", stringify!($name), self.0)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                Self::new(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
            }
        }
    };
}

policy_name!(
    /// The role of one sandbox in a setup, such as `main`, `build` or `fetch` (VM §1.4:
    /// phases with conflicting authority run in separate VMs).
    RoleName
);
policy_name!(
    /// The exact name of a resource: a route, file grant, volume, provider account,
    /// service, release channel, credential or device.
    ResourceName
);
policy_name!(
    /// The exact name of a typed provider operation (VM §0.1 item 3: validated operations
    /// bound to exact objects, not arbitrary requests).
    OperationName
);
policy_name!(
    /// The name of the template, tool or user that made a request.
    SourceName
);

/// Who acts (VM §2.4 "principal"): one sandbox of a setup, by its role.
///
/// A principal is a whole VM, never a process inside one: guest root controls every
/// process in the guest (VM §1.1), and parts with different authority belong in
/// different VMs (§1.4). An activated policy binds the role to one tenant and execution,
/// whose identity the host takes from its own channel, never from the guest (VM-P29).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Principal {
    pub role: RoleName,
}

impl Principal {
    pub fn role(name: &str) -> Result<Self, IdError> {
        Ok(Self {
            role: RoleName::new(name)?,
        })
    }
}

/// The kind of resource a [`ResourceRef`] names.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceKind {
    /// A named transport route; the route to a destination is named by its canonical
    /// route reference ([`ResourceRef::route`]).
    Route,
    /// A host file grant.
    FileGrant,
    /// A declared data volume.
    Volume,
    /// An external account a typed provider operation acts on.
    ProviderAccount,
    /// A published service.
    Service,
    /// A declared release channel.
    ReleaseChannel,
    /// An external credential.
    Credential,
    /// An explicitly assigned device.
    Device,
}

impl ResourceKind {
    /// The stable tag in canonical encodings.
    pub const fn tag(self) -> &'static str {
        match self {
            Self::Route => "route",
            Self::FileGrant => "file_grant",
            Self::Volume => "volume",
            Self::ProviderAccount => "provider_account",
            Self::Service => "service",
            Self::ReleaseChannel => "release_channel",
            Self::Credential => "credential",
            Self::Device => "device",
        }
    }
}

impl fmt::Display for ResourceKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Route => "route",
            Self::FileGrant => "file grant",
            Self::Volume => "volume",
            Self::ProviderAccount => "provider account",
            Self::Service => "service",
            Self::ReleaseChannel => "release channel",
            Self::Credential => "credential",
            Self::Device => "device",
        })
    }
}

/// The resource a permission is about (VM §2.4 "resource"); at run time, the endpoint.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceRef {
    pub kind: ResourceKind,
    pub name: ResourceName,
}

impl ResourceRef {
    pub fn new(kind: ResourceKind, name: &str) -> Result<Self, IdError> {
        Ok(Self {
            kind,
            name: ResourceName::new(name)?,
        })
    }

    /// The route resource for `authority`, named by the one shared spelling
    /// ([`route_reference`]: canonical `host:port`), so ceilings, requests, delegations
    /// and V08 declarations name one destination's route identically. Refuses a reference
    /// outside the identifier grammar, such as a bracketed IPv6 address or a name longer
    /// than [`MAX_ID_LEN`](crate::foundation::ids::MAX_ID_LEN).
    pub fn route(authority: &Authority) -> Result<Self, IdError> {
        Self::new(ResourceKind::Route, &route_reference(authority))
    }
}

impl fmt::Display for ResourceRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} \"{}\"", self.kind, self.name)
    }
}

strict_policy_enum! {
    /// What is done (VM §2.4 "operation"). Each operation applies to exactly one
    /// [`ResourceKind`]; the validator refuses any other combination.
    #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub enum Operation tag "kind" {
        /// Read through a host file grant.
        FileRead,
        /// Write through a host file grant.
        FileWrite,
        /// Write to a declared data volume that outlives the task (§1.3 persistence).
        VolumeWrite,
        /// Use a named transport route (§1.3 network authority).
        TransportConnect,
        /// A typed credentialed operation the host performs on an external account
        /// (§1.3 network authority; §0.1 item 3).
        ProviderOperation { name: OperationName },
        /// Publish a service (§1.3 network authority).
        PublishService,
        /// Release an output through a declared channel (§0.1 item 4).
        Release,
        /// Deliver an external credential into the guest (§1.3 credential exposure).
        ReceiveExternalCredential,
        /// Use an explicitly assigned device (§1.3 device exposure).
        DeviceUse,
    }
}

impl Operation {
    /// The one resource kind this operation applies to.
    pub fn resource_kind(&self) -> ResourceKind {
        match self {
            Self::FileRead | Self::FileWrite => ResourceKind::FileGrant,
            Self::VolumeWrite => ResourceKind::Volume,
            Self::TransportConnect => ResourceKind::Route,
            Self::ProviderOperation { .. } => ResourceKind::ProviderAccount,
            Self::PublishService => ResourceKind::Service,
            Self::Release => ResourceKind::ReleaseChannel,
            Self::ReceiveExternalCredential => ResourceKind::Credential,
            Self::DeviceUse => ResourceKind::Device,
        }
    }

    /// Network authority in the §1.3 sense: named routes, typed credentialed operations
    /// and published services. A task without any is offline.
    pub fn is_network_authority(&self) -> bool {
        matches!(
            self,
            Self::TransportConnect | Self::ProviderOperation { .. } | Self::PublishService
        )
    }

    /// Whether bytes leave the sandbox through this operation. Every such channel counts
    /// against the release bound (§2.2: all channels declared; §0.2: account for every
    /// release channel).
    pub fn is_outbound(&self) -> bool {
        self.is_network_authority() || matches!(self, Self::Release)
    }

    /// Whether each use spends `resource`: outbound operations spend release bytes,
    /// external effects (a release or a provider operation) also spend release effects,
    /// and delivering an external credential spends the effects it delegates (§4.5).
    pub fn consumes(&self, resource: BudgetResource) -> bool {
        match resource {
            BudgetResource::ReleaseBytes => self.is_outbound(),
            BudgetResource::ReleaseEffects => {
                matches!(self, Self::Release | Self::ProviderOperation { .. })
            }
            BudgetResource::ShortLivedCredentialEffects => {
                matches!(self, Self::ReceiveExternalCredential)
            }
            BudgetResource::IdleLifetimeSeconds
            | BudgetResource::AbsoluteLifetimeSeconds
            | BudgetResource::ServiceRenewalSeconds => false,
        }
    }

    /// The stable tag in canonical encodings.
    pub fn tag(&self) -> &'static str {
        match self {
            Self::FileRead => "file_read",
            Self::FileWrite => "file_write",
            Self::VolumeWrite => "volume_write",
            Self::TransportConnect => "transport_connect",
            Self::ProviderOperation { .. } => "provider_operation",
            Self::PublishService => "publish_service",
            Self::Release => "release",
            Self::ReceiveExternalCredential => "receive_external_credential",
            Self::DeviceUse => "device_use",
        }
    }
}

impl fmt::Display for Operation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FileRead => f.write_str("read"),
            Self::FileWrite => f.write_str("write"),
            Self::VolumeWrite => f.write_str("write persistent"),
            Self::TransportConnect => f.write_str("connect through"),
            Self::ProviderOperation { name } => write!(f, "perform operation \"{name}\" on"),
            Self::PublishService => f.write_str("publish"),
            Self::Release => f.write_str("release through"),
            Self::ReceiveExternalCredential => f.write_str("receive"),
            Self::DeviceUse => f.write_str("use"),
        }
    }
}

/// A workflow phase (VM §1.4: build, fetch, private analysis and publication phases can
/// run in separate VMs when their authorities conflict).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    Build,
    Fetch,
    /// The main run, which may hold private data.
    Analysis,
    Publication,
}

impl Phase {
    pub const ALL: [Self; 4] = [Self::Build, Self::Fetch, Self::Analysis, Self::Publication];

    /// The stable tag in canonical encodings.
    pub const fn tag(self) -> &'static str {
        match self {
            Self::Build => "build",
            Self::Fetch => "fetch",
            Self::Analysis => "analysis",
            Self::Publication => "publication",
        }
    }
}

/// Under which conditions a permission applies (VM §2.4 "context").
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Context {
    pub phase: Phase,
}

strict_policy_enum! {
    /// Which generations a permission applies to (VM §2.4 "generation"; §0.1 item 5:
    /// capabilities are generation-bound). Product ceilings and template requests are
    /// generation-independent; a delegation may bind one authorization epoch, and is
    /// then honoured at that epoch only (VM-P13: stale-generation capabilities fail).
    #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub enum GenerationScope tag "scope" {
        /// Every authorization epoch; activation binds it to the current one.
        EveryGeneration,
        /// Exactly this authorization epoch.
        Authorization { epoch: AuthorizationEpoch },
    }
}

impl fmt::Display for GenerationScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EveryGeneration => f.write_str("any authorization epoch"),
            Self::Authorization { epoch } => write!(f, "authorization epoch {epoch} only"),
        }
    }
}

/// A permission without its generation: what is done, by whom, to what, when.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Action {
    pub principal: Principal,
    pub operation: Operation,
    pub resource: ResourceRef,
    pub context: Context,
}

impl fmt::Display for Action {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "sandbox \"{}\" may {} {} during {}",
            self.principal.role,
            self.operation,
            self.resource,
            self.context.phase.tag()
        )
    }
}

/// One permitted tuple (principal, operation, resource, context, generation) (VM §2.4).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PermissionTuple {
    pub principal: Principal,
    pub operation: Operation,
    pub resource: ResourceRef,
    pub context: Context,
    pub generation: GenerationScope,
}

impl PermissionTuple {
    /// The tuple without its generation.
    pub fn action(&self) -> Action {
        Action {
            principal: self.principal.clone(),
            operation: self.operation.clone(),
            resource: self.resource.clone(),
            context: self.context,
        }
    }

    /// `action` at `generation`.
    pub fn of(action: Action, generation: GenerationScope) -> Self {
        Self {
            principal: action.principal,
            operation: action.operation,
            resource: action.resource,
            context: action.context,
            generation,
        }
    }

    /// Whether the operation applies to the resource's kind.
    pub fn is_well_typed(&self) -> bool {
        self.operation.resource_kind() == self.resource.kind
    }
}

impl fmt::Display for PermissionTuple {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.action(), self.generation)
    }
}

/// The generations one action is permitted at.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Coverage {
    Every,
    /// A non-empty set of exact epochs.
    Epochs(BTreeSet<AuthorizationEpoch>),
}

impl Coverage {
    fn meet(&self, other: &Self) -> Option<Self> {
        match (self, other) {
            (Self::Every, covered) | (covered, Self::Every) => Some(covered.clone()),
            (Self::Epochs(left), Self::Epochs(right)) => {
                let common: BTreeSet<AuthorizationEpoch> =
                    left.intersection(right).copied().collect();
                (!common.is_empty()).then_some(Self::Epochs(common))
            }
        }
    }

    fn join(&self, other: &Self) -> Self {
        match (self, other) {
            (Self::Every, _) | (_, Self::Every) => Self::Every,
            (Self::Epochs(left), Self::Epochs(right)) => {
                Self::Epochs(left.union(right).copied().collect())
            }
        }
    }

    fn covers(&self, generation: &GenerationScope) -> bool {
        match (self, generation) {
            (Self::Every, _) => true,
            (Self::Epochs(epochs), GenerationScope::Authorization { epoch }) => {
                epochs.contains(epoch)
            }
            (Self::Epochs(_), GenerationScope::EveryGeneration) => false,
        }
    }

    fn covers_epoch(&self, epoch: AuthorizationEpoch) -> bool {
        match self {
            Self::Every => true,
            Self::Epochs(epochs) => epochs.contains(&epoch),
        }
    }
}

/// A set of permitted tuples in canonical form (VM §2.4).
///
/// Duplicates collapse, and an exact-epoch tuple is dropped when the same action is
/// permitted at every generation, so equal denotations have equal values, encodings and
/// [`ContractIdentity`](super::ContractIdentity) digests whatever order the tuples came
/// in.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(from = "Vec<PermissionTuple>", into = "Vec<PermissionTuple>")]
pub struct PermissionSet {
    actions: BTreeMap<Action, Coverage>,
}

impl PermissionSet {
    pub fn new(tuples: impl IntoIterator<Item = PermissionTuple>) -> Self {
        let mut set = Self::default();
        for tuple in tuples {
            set.insert(tuple);
        }
        set
    }

    fn insert(&mut self, tuple: PermissionTuple) {
        let generation = tuple.generation;
        let action = tuple.action();
        match (self.actions.entry(action), generation) {
            (Entry::Vacant(slot), GenerationScope::EveryGeneration) => {
                slot.insert(Coverage::Every);
            }
            (Entry::Vacant(slot), GenerationScope::Authorization { epoch }) => {
                slot.insert(Coverage::Epochs(BTreeSet::from([epoch])));
            }
            (Entry::Occupied(mut slot), GenerationScope::EveryGeneration) => {
                slot.insert(Coverage::Every);
            }
            (Entry::Occupied(mut slot), GenerationScope::Authorization { epoch }) => {
                if let Coverage::Epochs(epochs) = slot.get_mut() {
                    epochs.insert(epoch);
                }
            }
        }
    }

    /// The tuples both sets permit (exact set intersection).
    pub fn intersection(&self, other: &Self) -> Self {
        let actions = self
            .actions
            .iter()
            .filter_map(|(action, coverage)| {
                let theirs = other.actions.get(action)?;
                coverage.meet(theirs).map(|common| (action.clone(), common))
            })
            .collect();
        Self { actions }
    }

    /// The tuples either set permits (exact set union).
    pub fn union(&self, other: &Self) -> Self {
        let mut actions = self.actions.clone();
        for (action, coverage) in &other.actions {
            let joined = match actions.get(action) {
                Some(mine) => mine.join(coverage),
                None => coverage.clone(),
            };
            actions.insert(action.clone(), joined);
        }
        Self { actions }
    }

    /// Whether every concrete tuple `tuple` denotes is permitted. A tuple for every
    /// generation is covered only by a permission for every generation, never by a list
    /// of epochs.
    pub fn covers(&self, tuple: &PermissionTuple) -> bool {
        self.actions
            .get(&tuple.action())
            .is_some_and(|coverage| coverage.covers(&tuple.generation))
    }

    /// Whether `action` is permitted at `epoch`.
    pub fn permits_at(&self, action: &Action, epoch: AuthorizationEpoch) -> bool {
        self.actions
            .get(action)
            .is_some_and(|coverage| coverage.covers_epoch(epoch))
    }

    /// Whether every tuple of `self` is permitted by `other`.
    pub fn is_subset(&self, other: &Self) -> bool {
        self.iter().all(|tuple| other.covers(&tuple))
    }

    /// The actions permitted at `epoch`; tuples bound to another epoch are stale there.
    pub fn actions_at(&self, epoch: AuthorizationEpoch) -> BTreeSet<Action> {
        self.actions
            .iter()
            .filter(|(_, coverage)| coverage.covers_epoch(epoch))
            .map(|(action, _)| action.clone())
            .collect()
    }

    /// The tuples in canonical order.
    pub fn iter(&self) -> impl Iterator<Item = PermissionTuple> + '_ {
        self.actions
            .iter()
            .flat_map(|(action, coverage)| -> Vec<PermissionTuple> {
                match coverage {
                    Coverage::Every => vec![PermissionTuple::of(
                        action.clone(),
                        GenerationScope::EveryGeneration,
                    )],
                    Coverage::Epochs(epochs) => epochs
                        .iter()
                        .map(|epoch| {
                            PermissionTuple::of(
                                action.clone(),
                                GenerationScope::Authorization { epoch: *epoch },
                            )
                        })
                        .collect(),
                }
            })
    }

    pub fn tuples(&self) -> Vec<PermissionTuple> {
        self.iter().collect()
    }

    /// The number of tuples in canonical form.
    pub fn len(&self) -> usize {
        self.actions
            .values()
            .map(|coverage| match coverage {
                Coverage::Every => 1,
                Coverage::Epochs(epochs) => epochs.len(),
            })
            .sum()
    }

    pub fn is_empty(&self) -> bool {
        self.actions.is_empty()
    }
}

impl From<Vec<PermissionTuple>> for PermissionSet {
    fn from(tuples: Vec<PermissionTuple>) -> Self {
        Self::new(tuples)
    }
}

impl From<PermissionSet> for Vec<PermissionTuple> {
    fn from(set: PermissionSet) -> Self {
        set.tuples()
    }
}

impl FromIterator<PermissionTuple> for PermissionSet {
    fn from_iter<I: IntoIterator<Item = PermissionTuple>>(tuples: I) -> Self {
        Self::new(tuples)
    }
}
