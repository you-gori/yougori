//! GPU-W09 (line 1117): "Implement expiring residency advertisements and stale-source
//! fallback."
//!
//! An [`AdvertisementBook`] keeps each residency advertisement with an expiry no later
//! than the policy's maximum time to live, refuses a re-advertisement of an older
//! activation generation and purges expired entries. It never decides on its own whether
//! an advertisement may be used: every use goes through
//! [`ResidentAdvertisement::recheck`] against the authoritative record (line 506). When
//! a load is planned from advertised peers, a peer whose advertisement is missing,
//! expired or otherwise refused is excluded from the GPU §2.5 multi-source plan, and the
//! load falls back to the remaining authorized sources, such as the origin.

use std::collections::BTreeMap;
use std::fmt;
use std::time::Duration;

use crate::foundation::ids::{Clock, GpuDeviceKey, ModelActivationGeneration, MonotonicTime};
use crate::model_memory::identity::{
    AdvertisementRefusal, AdvertisementRequest, CurrentResidency, ExecutionIdentity,
    RecheckedResidency, Residency, ResidentAdvertisement, ScopedGrant,
};
use crate::model_memory::math::sources::{
    CutSpec, MultiSourceLoad, SourceAuthorization, SourceSpec, StealPolicy,
};
use crate::model_memory::math::InputError;

use super::error::RoutingError;

/// How long an advertisement may live (W09 "expiring").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AdvertisementPolicy {
    max_ttl: Duration,
}

impl AdvertisementPolicy {
    /// Refuses a zero maximum.
    pub fn new(max_ttl: Duration) -> Result<Self, InputError> {
        if max_ttl.is_zero() {
            return Err(InputError::NotPositive { field: "max_ttl" });
        }
        Ok(Self { max_ttl })
    }

    pub fn max_ttl(&self) -> Duration {
        self.max_ttl
    }
}

/// One stored advertisement and when it was made.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdvertisementEntry {
    pub advertisement: ResidentAdvertisement,
    pub advertised_at: MonotonicTime,
}

/// Why an advertisement was not stored.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AdvertiseRefusal {
    ZeroTtl,
    TtlAboveMaximum {
        ttl: Duration,
        max_ttl: Duration,
    },
    /// A newer generation is already advertised for this residency.
    OlderGeneration {
        offered: ModelActivationGeneration,
        held: ModelActivationGeneration,
    },
    /// The expiry does not fit the clock.
    ClockOverflow,
}

impl fmt::Display for AdvertiseRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroTtl => f.write_str("an advertisement needs a time to live above zero"),
            Self::TtlAboveMaximum { ttl, max_ttl } => write!(
                f,
                "a time to live of {} s exceeds the maximum of {} s",
                ttl.as_secs_f64(),
                max_ttl.as_secs_f64()
            ),
            Self::OlderGeneration { offered, held } => write!(
                f,
                "activation {offered} is older than the advertised activation {held}"
            ),
            Self::ClockOverflow => f.write_str("the expiry does not fit the clock"),
        }
    }
}

impl std::error::Error for AdvertiseRefusal {}

/// The authoritative records advertisements are rechecked against (from the
/// coordinator, never from the advertisement).
pub trait AuthorityRecords {
    fn current(
        &self,
        device: &GpuDeviceKey,
        execution: &ExecutionIdentity,
    ) -> Option<CurrentResidency>;
}

impl AuthorityRecords for BTreeMap<(GpuDeviceKey, ExecutionIdentity), CurrentResidency> {
    fn current(
        &self,
        device: &GpuDeviceKey,
        execution: &ExecutionIdentity,
    ) -> Option<CurrentResidency> {
        self.get(&(*device, *execution)).cloned()
    }
}

/// Why an advertised source may not be used.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SourceRefusal {
    /// Nothing is advertised for this device and execution.
    NotAdvertised,
    /// The authority has no record of the residency.
    NoAuthorityRecord,
    /// The recheck failed (line 506), for example because the advertisement expired.
    Advertisement(AdvertisementRefusal),
}

/// A source that passed its recheck, with the advertisement's age.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UsableSource {
    pub device: GpuDeviceKey,
    pub rechecked: RecheckedResidency,
    pub age: Duration,
}

/// A source left out, and why.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RefusedSource {
    pub device: GpuDeviceKey,
    pub reason: SourceRefusal,
}

/// Residency advertisements with expiry (W09).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdvertisementBook {
    policy: AdvertisementPolicy,
    entries: BTreeMap<(GpuDeviceKey, ExecutionIdentity), AdvertisementEntry>,
}

impl AdvertisementBook {
    pub fn new(policy: AdvertisementPolicy) -> Self {
        Self {
            policy,
            entries: BTreeMap::new(),
        }
    }

    /// Stores or renews an advertisement of `residency` at `generation`, expiring `ttl`
    /// from now. The same generation renews; an older one than the stored one is refused.
    pub fn advertise(
        &mut self,
        residency: Residency,
        generation: ModelActivationGeneration,
        ttl: Duration,
        clock: &dyn Clock,
    ) -> Result<&AdvertisementEntry, AdvertiseRefusal> {
        if ttl.is_zero() {
            return Err(AdvertiseRefusal::ZeroTtl);
        }
        if ttl > self.policy.max_ttl {
            return Err(AdvertiseRefusal::TtlAboveMaximum {
                ttl,
                max_ttl: self.policy.max_ttl,
            });
        }
        let key = (residency.device, residency.execution);
        if let Some(held) = self.entries.get(&key) {
            if generation < held.advertisement.generation {
                return Err(AdvertiseRefusal::OlderGeneration {
                    offered: generation,
                    held: held.advertisement.generation,
                });
            }
        }
        let now = clock.now();
        let expires_at = now
            .checked_add(ttl)
            .ok_or(AdvertiseRefusal::ClockOverflow)?;
        let entry = AdvertisementEntry {
            advertisement: ResidentAdvertisement {
                residency,
                generation,
                expires_at,
            },
            advertised_at: now,
        };
        self.entries.insert(key, entry);
        self.entries
            .get(&key)
            .ok_or(AdvertiseRefusal::ClockOverflow)
    }

    /// Removes an advertisement, as when its residency is evicted.
    pub fn withdraw(
        &mut self,
        device: &GpuDeviceKey,
        execution: &ExecutionIdentity,
    ) -> Option<AdvertisementEntry> {
        self.entries.remove(&(*device, *execution))
    }

    /// Removes every advertisement at or past its expiry and returns their keys.
    pub fn purge_expired(&mut self, clock: &dyn Clock) -> Vec<(GpuDeviceKey, ExecutionIdentity)> {
        let now = clock.now();
        let expired: Vec<_> = self
            .entries
            .iter()
            .filter(|(_, entry)| entry.advertisement.expires_at <= now)
            .map(|(key, _)| *key)
            .collect();
        for key in &expired {
            self.entries.remove(key);
        }
        expired
    }

    pub fn get(
        &self,
        device: &GpuDeviceKey,
        execution: &ExecutionIdentity,
    ) -> Option<&AdvertisementEntry> {
        self.entries.get(&(*device, *execution))
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Rechecks the advertisement of `device` for `request` against `records`.
    pub fn recheck(
        &self,
        device: &GpuDeviceKey,
        request: &AdvertisementRequest,
        records: &dyn AuthorityRecords,
        grant: Option<&ScopedGrant>,
        clock: &dyn Clock,
    ) -> Result<UsableSource, SourceRefusal> {
        let entry = self
            .get(device, &request.required)
            .ok_or(SourceRefusal::NotAdvertised)?;
        let current = records
            .current(device, &request.required)
            .ok_or(SourceRefusal::NoAuthorityRecord)?;
        let rechecked = entry
            .advertisement
            .recheck(&current, request, grant, clock)
            .map_err(SourceRefusal::Advertisement)?;
        Ok(UsableSource {
            device: *device,
            rechecked,
            age: clock.now().saturating_duration_since(entry.advertised_at),
        })
    }
}

/// A peer that might supply the bytes, with its measured source figures.
#[derive(Clone, Debug, PartialEq)]
pub struct PeerSource {
    pub device: GpuDeviceKey,
    /// Its GPU §2.5 source description. The authorization given here is ignored: it
    /// comes from the advertisement recheck alone.
    pub spec: SourceSpec,
    pub grant: Option<ScopedGrant>,
}

/// A load planned with stale sources excluded (W09 "stale-source fallback").
#[derive(Clone, Debug)]
pub struct FallbackPlan {
    pub load: MultiSourceLoad,
    pub usable: Vec<UsableSource>,
    pub refused: Vec<RefusedSource>,
    /// No peer was usable, so only the origin and other non-peer sources load.
    pub peers_exhausted: bool,
}

/// Plans a load over the advertised peers and `origin`. Each peer is authorized only if
/// its advertisement passes the recheck; a missing, expired or otherwise refused one is
/// excluded and named, and the plan falls back to the remaining sources. The origin keeps
/// the authorization its own authority gave it.
#[allow(clippy::too_many_arguments)]
pub fn plan_with_fallback(
    book: &AdvertisementBook,
    request: &AdvertisementRequest,
    records: &dyn AuthorityRecords,
    peers: Vec<PeerSource>,
    origin: SourceSpec,
    cuts: Vec<CutSpec>,
    batches_bytes: &[u64],
    policy: StealPolicy,
    clock: &dyn Clock,
) -> Result<FallbackPlan, RoutingError> {
    let mut usable = Vec::new();
    let mut refused = Vec::new();
    let mut specs = Vec::with_capacity(peers.len().saturating_add(1));
    for peer in peers {
        let mut spec = peer.spec;
        match book.recheck(&peer.device, request, records, peer.grant.as_ref(), clock) {
            Ok(source) => {
                spec.authorization = SourceAuthorization::Authorized;
                usable.push(source);
            }
            Err(reason) => {
                spec.authorization = SourceAuthorization::Unauthorized;
                refused.push(RefusedSource {
                    device: peer.device,
                    reason,
                });
            }
        }
        specs.push(spec);
    }
    specs.push(origin);
    let load = MultiSourceLoad::plan(specs, cuts, batches_bytes, policy)?;
    Ok(FallbackPlan {
        peers_exhausted: usable.is_empty(),
        load,
        usable,
        refused,
    })
}
