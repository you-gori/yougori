//! The canary registry and planting planner (VM-W10; VM-R86; VM-CP-21 line 2996).
//!
//! One registry serves every sandbox on a host: it issues each value once, keeps every
//! canary it issued (retired ones included) so an old value is still attributed to the
//! instance it was planted in, and refuses to bind values to a binding twice. Values
//! include their binding (sandbox, VM instance, boot generation) and a block from the
//! seeded generator, and the registry refuses any value it has issued before, so two
//! clones restored from one snapshot and re-planted never share a value.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::net::{IpAddr, SocketAddr};

use serde::{Deserialize, Serialize};

use super::calibration::{CalibrationId, CalibrationRecord};
use super::canary::{
    Canary, CanaryId, CanaryKind, CanaryState, CanaryValue, SandboxBinding, HONEYPORT_FIRST_PORT,
    HONEYPORT_LAST_PORT,
};
use super::generator::{CanaryGenerator, CanarySeed};
use super::placement::{check_placement, PlacementLocation, PlacementRefusal};
use crate::foundation::coordination::{SnapshotId, VmInstanceId};
use crate::foundation::ids::{digest, Digest, DigestBuilder, SandboxBootGeneration};
use crate::sandbox_contract::destinations::{classify, AddressClass, HostAddressState};
use crate::sandbox_contract::effects::SandboxRef;
use crate::sandbox_contract::provider::find_encoded;

/// Most canaries in one plan.
pub const MAX_CANARIES_PER_PLAN: usize = 16;
/// Most canaries one registry keeps, retired ones included; see [`CanaryRegistry::with_capacity`].
pub const MAX_REGISTERED_CANARIES: usize = 65_536;
/// Most relay-owned honeyport addresses.
pub const MAX_HONEYPORT_ADDRESSES: usize = 256;

/// Draws before a kind's value space counts as exhausted.
const MAX_DRAWS_PER_VALUE: u64 = 64;
/// Ports in the honeyport range: 16,384.
const HONEYPORT_PORT_SPAN: u16 = HONEYPORT_LAST_PORT - HONEYPORT_FIRST_PORT + 1;

const MARKER_DOMAIN: &str = "yougori/sandbox/canary/marker/v1";
const FINGERPRINT_DOMAIN: &str = "yougori/sandbox/canary/fingerprint/v1";
const PROFILE_DOMAIN: &str = "yougori/sandbox/canary/profile/v1";
const PLAN_DOMAIN: &str = "yougori/sandbox/canary/plan/v1";

/// The V02 address classes a honeyport may use: private and shared CGNAT space. V02
/// classifies metadata endpoints, the host's own addresses and IPv4 carried in IPv6 as
/// classes of their own, so none of them is accepted. Link-local space is refused too:
/// platform services use link-local addresses beyond V02's metadata list (node-local DNS
/// on 169.254.20.10, for example).
const HONEYPORT_CLASSES: [AddressClass; 2] = [AddressClass::Private, AddressClass::SharedCgnat];

/// Why a honeyport address was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HoneyportRefusal {
    /// V02 (`destinations::classify`) puts the address in a class no honeyport may use:
    /// public space could reach a third party (§8.2 "controlled internal canaries"), a
    /// metadata endpoint is refused in every mode, a host-owned address is a host service,
    /// and every other special class is refused too.
    AddressClassRefused {
        /// The refused address.
        address: IpAddr,
        /// Its V02 class.
        class: AddressClass,
    },
    /// An address listed twice.
    Duplicate {
        /// The repeated address.
        address: IpAddr,
    },
    /// More than [`MAX_HONEYPORT_ADDRESSES`] addresses.
    TooMany {
        /// The bound.
        max: usize,
    },
}

impl fmt::Display for HoneyportRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AddressClassRefused { address, class } => write!(
                f,
                "{address} is {class}; a honeyport needs a private or shared CGNAT address \
                 that is neither a metadata endpoint nor the host's own"
            ),
            Self::Duplicate { address } => write!(f, "{address} is listed twice"),
            Self::TooMany { max } => write!(f, "more than {max} honeyport addresses"),
        }
    }
}

impl std::error::Error for HoneyportRefusal {}

/// The relay-owned private addresses honeyport endpoints are placed on (VM-R43). The
/// relay must own them inside the perimeter and observe connection attempts to them
/// (later runtime work).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HoneyportPool {
    addresses: Vec<IpAddr>,
}

impl HoneyportPool {
    /// No honeyports; planning one is refused.
    pub fn none() -> Self {
        Self::default()
    }

    /// Classifies every address with V02 against `host`, the host's own addresses, and
    /// accepts only private and shared CGNAT ones. Refuses every other class, link-local
    /// included,
    /// duplicates and more than [`MAX_HONEYPORT_ADDRESSES`].
    pub fn new(addresses: Vec<IpAddr>, host: &HostAddressState) -> Result<Self, HoneyportRefusal> {
        if addresses.len() > MAX_HONEYPORT_ADDRESSES {
            return Err(HoneyportRefusal::TooMany {
                max: MAX_HONEYPORT_ADDRESSES,
            });
        }
        let mut seen = BTreeSet::new();
        for address in &addresses {
            let class = classify(*address, host).class;
            if !HONEYPORT_CLASSES.contains(&class) {
                return Err(HoneyportRefusal::AddressClassRefused {
                    address: *address,
                    class,
                });
            }
            if !seen.insert(*address) {
                return Err(HoneyportRefusal::Duplicate { address: *address });
            }
        }
        Ok(Self { addresses })
    }

    /// The addresses, in the order given.
    pub fn addresses(&self) -> &[IpAddr] {
        &self.addresses
    }
}

/// One canary to plant.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlacementRequest {
    /// What to plant.
    pub kind: CanaryKind,
    /// Where to plant it.
    pub location: PlacementLocation,
}

strict_canary_enum! {
    /// How the sandbox instance being planted came to be (VM-CP-21).
    #[derive(Clone, Debug, PartialEq, Eq, Hash)]
    pub enum PlantOrigin tag "origin" {
        /// A fresh boot, not a restore.
        FreshBoot,
        /// Restored from `snapshot`, which was taken of `source`: the snapshot carries the
        /// canaries planted in `source`, and they stay attributed to it.
        RestoredFrom {
            /// The snapshot restored.
            snapshot: SnapshotId,
            /// The binding the snapshot was taken of.
            source: SandboxBinding,
        },
    }
}

/// A request to plant canaries in one sandbox instance and boot generation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlantingRequest {
    /// The sandbox instance and boot generation being planted.
    pub binding: SandboxBinding,
    /// How the instance came to be.
    pub origin: PlantOrigin,
    /// The canaries to plant, at most [`MAX_CANARIES_PER_PLAN`].
    pub placements: Vec<PlacementRequest>,
}

/// The digest of a plan's kinds and locations, independent of values and bindings: what a
/// calibration measured (VM-W10 "calibrated response").
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ProfileDigest(Digest);

impl ProfileDigest {
    /// The profile of a set of placements, in any order.
    pub fn of(placements: &[PlacementRequest]) -> Self {
        let mut pairs: Vec<(CanaryKind, &PlacementLocation)> = placements
            .iter()
            .map(|placement| (placement.kind, &placement.location))
            .collect();
        pairs.sort();
        let builder = pairs.iter().fold(
            DigestBuilder::new(PROFILE_DOMAIN).u64(u64::try_from(pairs.len()).unwrap_or(u64::MAX)),
            |builder, (kind, location)| location.feed(builder.u64(kind.code())),
        );
        Self(builder.finish())
    }

    /// The digest the profile is.
    pub const fn digest(&self) -> &Digest {
        &self.0
    }
}

impl fmt::Debug for ProfileDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ProfileDigest({})", self.0)
    }
}

/// One instruction for the guest agent's planting step (later work, line 2890).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlantingInstruction {
    canary: CanaryId,
    kind: CanaryKind,
    location: PlacementLocation,
    value: CanaryValue,
}

impl PlantingInstruction {
    /// The canary's identity.
    pub const fn canary(&self) -> CanaryId {
        self.canary
    }

    /// The canary's kind.
    pub const fn kind(&self) -> CanaryKind {
        self.kind
    }

    /// Where to plant it.
    pub fn location(&self) -> &PlacementLocation {
        &self.location
    }

    /// The value to plant; never log it.
    pub fn value(&self) -> &CanaryValue {
        &self.value
    }
}

/// A validated planting plan for one binding. It holds values, so it is not serializable;
/// [`PlantingPlan::summary`] is its loggable form.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlantingPlan {
    binding: SandboxBinding,
    origin: PlantOrigin,
    profile: ProfileDigest,
    instructions: Vec<PlantingInstruction>,
}

impl PlantingPlan {
    /// The binding the plan is for.
    pub fn binding(&self) -> &SandboxBinding {
        &self.binding
    }

    /// How the instance came to be.
    pub fn origin(&self) -> &PlantOrigin {
        &self.origin
    }

    /// The plan's kinds and locations, as a digest.
    pub const fn profile(&self) -> ProfileDigest {
        self.profile
    }

    /// One instruction per canary, in request order.
    pub fn instructions(&self) -> &[PlantingInstruction] {
        &self.instructions
    }

    /// The plan with every value replaced by its digest.
    pub fn summary(&self) -> PlanSummary {
        PlanSummary {
            binding: self.binding.clone(),
            origin: self.origin.clone(),
            profile: self.profile,
            entries: self
                .instructions
                .iter()
                .map(|instruction| PlanEntry {
                    canary: instruction.canary,
                    kind: instruction.kind,
                    location: instruction.location.clone(),
                    value_digest: instruction.value.digest(),
                })
                .collect(),
        }
    }
}

/// One planted canary in a [`PlanSummary`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlanEntry {
    /// The canary's identity.
    pub canary: CanaryId,
    /// Its kind.
    pub kind: CanaryKind,
    /// Where it was planted.
    pub location: PlacementLocation,
    /// The keyed digest of its value.
    pub value_digest: Digest,
}

/// A plan without its values: identifiers, locations and value digests.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlanSummary {
    /// The binding planted.
    pub binding: SandboxBinding,
    /// How the instance came to be.
    pub origin: PlantOrigin,
    /// The plan's kinds and locations.
    pub profile: ProfileDigest,
    /// One entry per canary, in request order.
    pub entries: Vec<PlanEntry>,
}

impl PlanSummary {
    /// The digest of the summary, for an audit record of the planting.
    pub fn digest(&self) -> Digest {
        let builder = self.binding.feed(DigestBuilder::new(PLAN_DOMAIN));
        let builder = match &self.origin {
            PlantOrigin::FreshBoot => builder.str("fresh_boot"),
            PlantOrigin::RestoredFrom { snapshot, source } => {
                source.feed(builder.str("restored_from").digest(&snapshot.digest()))
            }
        };
        self.entries
            .iter()
            .fold(
                builder
                    .digest(self.profile.digest())
                    .u64(u64::try_from(self.entries.len()).unwrap_or(u64::MAX)),
                |builder, entry| {
                    entry
                        .location
                        .feed(builder.digest(entry.canary.digest()).u64(entry.kind.code()))
                        .digest(&entry.value_digest)
                },
            )
            .finish()
    }
}

strict_canary_enum! {
    /// Why a planting request was refused. Nothing was registered.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum PlanRefusal tag "refusal" {
        /// The plan has no canaries.
        Empty,
        /// More than [`MAX_CANARIES_PER_PLAN`] canaries.
        TooMany {
            /// The bound.
            max: u64,
        },
        /// A placement was refused.
        Placement {
            /// Why.
            placement: PlacementRefusal,
        },
        /// This binding already has a plan; new values need a new boot generation.
        AlreadyPlanted,
        /// The instance was already planted at this or a later boot generation.
        StaleGeneration {
            /// The latest boot generation planted.
            latest: SandboxBootGeneration,
        },
        /// A restore cannot come from the binding being planted.
        RestoreSourceIsSelf,
        /// A restore of the same instance needs a later boot generation than its source.
        RestoreSourceNotOlder,
        /// A honeyport was requested but the registry has no relay-owned addresses.
        NoHoneyportPool,
        /// The registry holds its maximum of canaries.
        RegistryFull {
            /// The registry's capacity.
            max: u64,
        },
        /// No value of this kind that was never issued was found in the bounded draws.
        ValueSpaceExhausted {
            /// The kind whose values ran out.
            kind: CanaryKind,
        },
        /// The generator or the serial counter reached its end.
        GeneratorExhausted,
    }
}

impl fmt::Display for PlanRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("the plan has no canaries"),
            Self::TooMany { max } => write!(f, "a plan holds at most {max} canaries"),
            Self::Placement { placement } => write!(f, "{placement}"),
            Self::AlreadyPlanted => f.write_str(
                "this instance and boot generation already has canaries; re-planting needs a \
                 new boot generation",
            ),
            Self::StaleGeneration { latest } => write!(
                f,
                "this instance was already planted at boot generation {latest}"
            ),
            Self::RestoreSourceIsSelf => f.write_str("a restore cannot come from itself"),
            Self::RestoreSourceNotOlder => f.write_str(
                "a restore of the same instance needs a later boot generation than its source",
            ),
            Self::NoHoneyportPool => f.write_str("no relay-owned honeyport addresses"),
            Self::RegistryFull { max } => write!(f, "the registry holds {max} canaries"),
            Self::ValueSpaceExhausted { kind } => {
                write!(f, "no unused {kind} value was found")
            }
            Self::GeneratorExhausted => f.write_str("the canary generator is exhausted"),
        }
    }
}

impl std::error::Error for PlanRefusal {}

/// Why presented credential bytes were refused (§4.5 line 2002: a fake canary is never a
/// genuine credential).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CredentialUseRefusal {
    /// The bytes carry a canary value: it can never authorize anything.
    CanaryValue {
        /// The canary found.
        canary: CanaryId,
        /// Its kind.
        kind: CanaryKind,
    },
}

impl fmt::Display for CredentialUseRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CanaryValue { canary, kind } => write!(
                f,
                "the credential carries {kind} canary {canary}; a canary never authorizes \
                 anything"
            ),
        }
    }
}

impl std::error::Error for CredentialUseRefusal {}

/// Why a calibration was not attached to a plan.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CalibrationMismatch {
    /// The binding has no plan.
    NoPlan,
    /// The record measured other kinds or locations.
    ProfileDiffers,
}

impl fmt::Display for CalibrationMismatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoPlan => f.write_str("no plan for this binding"),
            Self::ProfileDiffers => {
                f.write_str("the calibration measured other canary kinds or locations")
            }
        }
    }
}

impl std::error::Error for CalibrationMismatch {}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct PlanRecord {
    pub(super) origin: PlantOrigin,
    pub(super) profile: ProfileDigest,
    pub(super) canaries: Vec<CanaryId>,
    pub(super) calibration: Option<CalibrationId>,
}

/// The host's canary registry (VM-W10).
pub struct CanaryRegistry {
    generator: CanaryGenerator,
    honeyports: HoneyportPool,
    capacity: usize,
    serial: u64,
    pub(super) canaries: BTreeMap<CanaryId, Canary>,
    pub(super) plans: BTreeMap<SandboxBinding, PlanRecord>,
    latest_boot: BTreeMap<(SandboxRef, VmInstanceId), SandboxBootGeneration>,
    /// Unkeyed fingerprints of every value ever issued; in memory only, never logged.
    fingerprints: BTreeSet<Digest>,
}

impl fmt::Debug for CanaryRegistry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "CanaryRegistry {{ canaries: {}, plans: {}, honeyport_addresses: {} }}",
            self.canaries.len(),
            self.plans.len(),
            self.honeyports.addresses.len()
        )
    }
}

impl CanaryRegistry {
    /// A registry drawing values from `seed`, with honeyports on `honeyports`.
    pub fn new(seed: &CanarySeed, honeyports: HoneyportPool) -> Self {
        Self {
            generator: CanaryGenerator::new(seed),
            honeyports,
            capacity: MAX_REGISTERED_CANARIES,
            serial: 0,
            canaries: BTreeMap::new(),
            plans: BTreeMap::new(),
            latest_boot: BTreeMap::new(),
            fingerprints: BTreeSet::new(),
        }
    }

    /// Lowers the capacity below [`MAX_REGISTERED_CANARIES`]; a larger value is clamped.
    pub fn with_capacity(mut self, capacity: usize) -> Self {
        self.capacity = capacity.min(MAX_REGISTERED_CANARIES);
        self
    }

    /// Validates `request` and issues fresh values for it. A newer boot generation of an
    /// instance retires the canaries of its older generations, which still match.
    pub fn plan(&mut self, request: PlantingRequest) -> Result<PlantingPlan, PlanRefusal> {
        let PlantingRequest {
            binding,
            origin,
            placements,
        } = request;
        self.check_request(&binding, &origin, &placements)?;
        let profile = ProfileDigest::of(&placements);

        let mut serial = self.serial;
        let mut fresh_prints = BTreeSet::new();
        let mut fresh = Vec::with_capacity(placements.len());
        for placement in placements {
            serial = serial
                .checked_add(1)
                .ok_or(PlanRefusal::GeneratorExhausted)?;
            let id = CanaryId::from_digest(
                binding
                    .feed(DigestBuilder::new(CanaryId::DOMAIN))
                    .u64(serial)
                    .finish(),
            );
            let (value, print) = draw_value(
                &mut self.generator,
                &self.honeyports,
                &self.fingerprints,
                &fresh_prints,
                placement.kind,
                &binding,
                serial,
            )?;
            fresh_prints.insert(print);
            fresh.push(Canary {
                id,
                kind: placement.kind,
                binding: binding.clone(),
                location: placement.location,
                value,
                state: CanaryState::Active,
            });
        }

        // Nothing is registered before every value exists.
        self.serial = serial;
        self.fingerprints.extend(fresh_prints);
        let older: Vec<SandboxBinding> = self
            .plans
            .keys()
            .filter(|planted| planted.same_instance(&binding) && planted.boot < binding.boot)
            .cloned()
            .collect();
        for planted in &older {
            self.retire(planted);
        }
        self.latest_boot
            .insert((binding.sandbox.clone(), binding.instance), binding.boot);
        let instructions: Vec<PlantingInstruction> = fresh
            .iter()
            .map(|canary| PlantingInstruction {
                canary: canary.id,
                kind: canary.kind,
                location: canary.location.clone(),
                value: canary.value.clone(),
            })
            .collect();
        self.plans.insert(
            binding.clone(),
            PlanRecord {
                origin: origin.clone(),
                profile,
                canaries: fresh.iter().map(|canary| canary.id).collect(),
                calibration: None,
            },
        );
        self.canaries
            .extend(fresh.into_iter().map(|canary| (canary.id, canary)));
        Ok(PlantingPlan {
            binding,
            origin,
            profile,
            instructions,
        })
    }

    fn check_request(
        &self,
        binding: &SandboxBinding,
        origin: &PlantOrigin,
        placements: &[PlacementRequest],
    ) -> Result<(), PlanRefusal> {
        if placements.is_empty() {
            return Err(PlanRefusal::Empty);
        }
        if placements.len() > MAX_CANARIES_PER_PLAN {
            return Err(PlanRefusal::TooMany {
                max: u64::try_from(MAX_CANARIES_PER_PLAN).unwrap_or(u64::MAX),
            });
        }
        if self.plans.contains_key(binding) {
            return Err(PlanRefusal::AlreadyPlanted);
        }
        if let Some(latest) = self
            .latest_boot
            .get(&(binding.sandbox.clone(), binding.instance))
        {
            if binding.boot <= *latest {
                return Err(PlanRefusal::StaleGeneration { latest: *latest });
            }
        }
        if let PlantOrigin::RestoredFrom { source, .. } = origin {
            if source == binding {
                return Err(PlanRefusal::RestoreSourceIsSelf);
            }
            if source.same_instance(binding) && source.boot >= binding.boot {
                return Err(PlanRefusal::RestoreSourceNotOlder);
            }
        }
        let mut seen = BTreeSet::new();
        for placement in placements {
            check_placement(placement.kind, &placement.location)
                .map_err(|placement| PlanRefusal::Placement { placement })?;
            if !seen.insert(placement.location.folded()) {
                return Err(PlanRefusal::Placement {
                    placement: PlacementRefusal::DuplicateLocation {
                        location: placement.location.clone(),
                    },
                });
            }
        }
        if self.honeyports.addresses.is_empty()
            && placements
                .iter()
                .any(|placement| placement.kind == CanaryKind::HoneyportEndpoint)
        {
            return Err(PlanRefusal::NoHoneyportPool);
        }
        let after = self.canaries.len().saturating_add(placements.len());
        if after > self.capacity {
            return Err(PlanRefusal::RegistryFull {
                max: u64::try_from(self.capacity).unwrap_or(u64::MAX),
            });
        }
        Ok(())
    }

    /// Retires the canaries planted in `binding` (its instance stopped or was replaced).
    /// They still match, and their hits stay attributed to `binding`. Returns how many were
    /// active.
    pub fn retire(&mut self, binding: &SandboxBinding) -> usize {
        let Some(plan) = self.plans.get(binding) else {
            return 0;
        };
        let mut retired = 0usize;
        for id in &plan.canaries {
            if let Some(canary) = self.canaries.get_mut(id) {
                if canary.state == CanaryState::Active {
                    canary.state = CanaryState::Retired;
                    retired = retired.saturating_add(1);
                }
            }
        }
        retired
    }

    /// Refuses `presented` credential bytes that carry any canary value, in any encoding
    /// the provider scan covers (§4.5: a canary never authorizes anything). The vault, an
    /// executor or a credential import calls this before accepting a credential.
    pub fn refuse_credential_use(&self, presented: &[u8]) -> Result<(), CredentialUseRefusal> {
        match self
            .canaries
            .values()
            .find(|canary| find_encoded(presented, canary.value.as_bytes()).is_some())
        {
            Some(canary) => Err(CredentialUseRefusal::CanaryValue {
                canary: canary.id,
                kind: canary.kind,
            }),
            None => Ok(()),
        }
    }

    /// Marks hits of `binding`'s canaries with `record`, which must have measured the same
    /// kinds and locations.
    pub fn attach_calibration(
        &mut self,
        binding: &SandboxBinding,
        record: &CalibrationRecord,
    ) -> Result<(), CalibrationMismatch> {
        let plan = self
            .plans
            .get_mut(binding)
            .ok_or(CalibrationMismatch::NoPlan)?;
        if plan.profile != record.profile {
            return Err(CalibrationMismatch::ProfileDiffers);
        }
        plan.calibration = Some(record.id());
        Ok(())
    }

    /// The canary with identity `id`, retired ones included.
    pub fn canary(&self, id: CanaryId) -> Option<&Canary> {
        self.canaries.get(&id)
    }

    /// Every canary, retired ones included, in identity order.
    pub fn canaries(&self) -> impl Iterator<Item = &Canary> {
        self.canaries.values()
    }

    /// How many canaries the registry keeps, retired ones included.
    pub fn len(&self) -> usize {
        self.canaries.len()
    }

    /// Whether the registry has issued no canary.
    pub fn is_empty(&self) -> bool {
        self.canaries.is_empty()
    }

    /// The loggable form of `binding`'s plan.
    pub fn plan_summary(&self, binding: &SandboxBinding) -> Option<PlanSummary> {
        let plan = self.plans.get(binding)?;
        Some(PlanSummary {
            binding: binding.clone(),
            origin: plan.origin.clone(),
            profile: plan.profile,
            entries: plan
                .canaries
                .iter()
                .filter_map(|id| self.canaries.get(id))
                .map(|canary| PlanEntry {
                    canary: canary.id,
                    kind: canary.kind,
                    location: canary.location.clone(),
                    value_digest: canary.value.digest(),
                })
                .collect(),
        })
    }

    pub(super) fn plan_profile(&self, binding: &SandboxBinding) -> Option<ProfileDigest> {
        self.plans.get(binding).map(|plan| plan.profile)
    }
}

/// Draws a value of `kind` never issued before, by this registry or earlier in this plan.
fn draw_value(
    generator: &mut CanaryGenerator,
    honeyports: &HoneyportPool,
    issued: &BTreeSet<Digest>,
    fresh: &BTreeSet<Digest>,
    kind: CanaryKind,
    binding: &SandboxBinding,
    serial: u64,
) -> Result<(CanaryValue, Digest), PlanRefusal> {
    for attempt in 0..MAX_DRAWS_PER_VALUE {
        let block = generator
            .next_block()
            .ok_or(PlanRefusal::GeneratorExhausted)?;
        let marker = binding
            .feed(
                DigestBuilder::new(MARKER_DOMAIN)
                    .bytes(&block)
                    .u64(kind.code()),
            )
            .u64(serial)
            .u64(attempt)
            .finish();
        let value = match kind {
            CanaryKind::FakeCredential => CanaryValue::fake_credential(marker),
            CanaryKind::DocumentMarker => CanaryValue::document_marker(marker),
            CanaryKind::DnsName => CanaryValue::dns_name(marker),
            CanaryKind::HoneyportEndpoint => {
                CanaryValue::endpoint(marker, honeyport_endpoint(honeyports, &marker)?)
            }
        };
        let print = digest(FINGERPRINT_DOMAIN, &[value.as_bytes()]);
        if !issued.contains(&print) && !fresh.contains(&print) {
            return Ok((value, print));
        }
    }
    Err(PlanRefusal::ValueSpaceExhausted { kind })
}

/// A pool address and a port in the dynamic range, both taken from the marker.
fn honeyport_endpoint(pool: &HoneyportPool, marker: &Digest) -> Result<SocketAddr, PlanRefusal> {
    let [a0, a1, a2, a3, a4, a5, a6, a7, p0, p1, ..] = *marker.as_bytes();
    let count = u64::try_from(pool.addresses.len()).unwrap_or(u64::MAX);
    let index = u64::from_be_bytes([a0, a1, a2, a3, a4, a5, a6, a7])
        .checked_rem(count)
        .and_then(|index| usize::try_from(index).ok())
        .ok_or(PlanRefusal::NoHoneyportPool)?;
    let address = pool
        .addresses
        .get(index)
        .ok_or(PlanRefusal::NoHoneyportPool)?;
    let port = u16::from_be_bytes([p0, p1])
        .checked_rem(HONEYPORT_PORT_SPAN)
        .and_then(|offset| HONEYPORT_FIRST_PORT.checked_add(offset))
        .ok_or(PlanRefusal::ValueSpaceExhausted {
            kind: CanaryKind::HoneyportEndpoint,
        })?;
    Ok(SocketAddr::new(*address, port))
}
