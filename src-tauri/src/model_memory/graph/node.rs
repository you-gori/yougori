//! What each node of the request DAG carries (GPU §2.3): a kind, a duration estimate with
//! its uncertainty interval, resource demand over time, a semantic/compatibility identity,
//! a trust scope, a cancellation boundary and the completion event that establishes
//! usability.

use std::time::Duration;

use crate::foundation::ids::Digest;

use super::{GraphError, NodeId, ResourceId, TrustScope};

/// The kinds of required state and work in one request (GPU §2.3), plus the
/// network/client response work that the objective includes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum NodeKind {
    ArtifactExtent,
    EngineInitialization,
    RankLayout,
    Adapter,
    TokenizerConfiguration,
    KvBlock,
    GraphCapture,
    Communicator,
    Compute,
    NetworkResponse,
}

impl NodeKind {
    /// Every kind, in declaration order.
    pub const ALL: [Self; 10] = [
        Self::ArtifactExtent,
        Self::EngineInitialization,
        Self::RankLayout,
        Self::Adapter,
        Self::TokenizerConfiguration,
        Self::KvBlock,
        Self::GraphCapture,
        Self::Communicator,
        Self::Compute,
        Self::NetworkResponse,
    ];

    /// Whether existing ready state may satisfy this kind (GPU §1, path 1). Compute and
    /// response work belong to one request: ready weights do not eliminate prompt
    /// computation (§1.1).
    pub const fn can_be_ready(self) -> bool {
        !matches!(self, Self::Compute | Self::NetworkResponse)
    }

    /// Whether `event` establishes usability for this kind (GPU §2.3).
    pub const fn accepts(self, event: CompletionEvent) -> bool {
        matches!(
            (self, event),
            (Self::ArtifactExtent, CompletionEvent::ExtentVerified)
                | (Self::EngineInitialization, CompletionEvent::EngineReady)
                | (Self::RankLayout, CompletionEvent::LayoutPublished)
                | (Self::Adapter, CompletionEvent::AdapterActivated)
                | (
                    Self::TokenizerConfiguration,
                    CompletionEvent::TokenizerLoaded
                )
                | (Self::KvBlock, CompletionEvent::KvBlockPublished)
                | (Self::GraphCapture, CompletionEvent::GraphKeyValidated)
                | (Self::Communicator, CompletionEvent::CommunicatorReady)
                | (Self::Compute, CompletionEvent::ComputeCompleted)
                | (Self::NetworkResponse, CompletionEvent::FirstTokenDelivered)
                | (Self::NetworkResponse, CompletionEvent::ResponseDelivered)
        )
    }
}

/// The event that establishes a node's state as usable (GPU §2.3). A node's finish time
/// is the time of this event, so consumers wait for usability, not for activity to stop.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CompletionEvent {
    /// The extent's bytes matched its integrity identity; arrival alone is not usability.
    ExtentVerified,
    EngineReady,
    LayoutPublished,
    AdapterActivated,
    TokenizerLoaded,
    KvBlockPublished,
    /// The execution key and every graph resource were validated; stable addresses alone
    /// do not establish correctness (GPU §1.1).
    GraphKeyValidated,
    CommunicatorReady,
    ComputeCompleted,
    /// The first correct token reached the client: the objective (GPU §2.3).
    FirstTokenDelivered,
    /// Other response work, such as later tokens.
    ResponseDelivered,
}

/// A duration estimate with its uncertainty interval (GPU §2.3):
/// `low <= expected <= high` and `expected > 0`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DurationEstimate {
    low: Duration,
    expected: Duration,
    high: Duration,
}

impl DurationEstimate {
    /// Refuses `expected == 0` and any interval other than `low <= expected <= high`.
    pub fn new(low: Duration, expected: Duration, high: Duration) -> Result<Self, GraphError> {
        if expected.is_zero() {
            return Err(GraphError::InvalidDuration {
                reason: "the expected duration must be more than zero",
            });
        }
        if low > expected || expected > high {
            return Err(GraphError::InvalidDuration {
                reason: "the interval must satisfy low <= expected <= high",
            });
        }
        Ok(Self {
            low,
            expected,
            high,
        })
    }

    /// An estimate without uncertainty.
    pub fn exact(expected: Duration) -> Result<Self, GraphError> {
        Self::new(expected, expected, expected)
    }

    /// The optimistic end of the interval.
    pub const fn low(&self) -> Duration {
        self.low
    }

    /// The estimate schedules and capacity checks use.
    pub const fn expected(&self) -> Duration {
        self.expected
    }

    /// The pessimistic end of the interval; policy limits are judged here.
    pub const fn high(&self) -> Duration {
        self.high
    }
}

/// The unit a resource's capacity and every demand on it are counted in.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ResourceUnit {
    /// Memory, such as VRAM or pinned host memory.
    Bytes,
    /// A link or device rate, such as one PCIe direction; advertised rates are never
    /// summed across shared cuts (§2.5), so each shared cut is one resource.
    BytesPerSecond,
    /// Exclusive or pooled slots, such as decoder threads or one copy engine.
    Slots,
}

/// When a demand segment ends.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SegmentEnd {
    /// At this offset from the node's start, within its expected duration: a transient
    /// allocation or a rate held while the work runs.
    AfterStart(Duration),
    /// Held until the request ends, like weights that stay resident for their consumers.
    RequestEnd,
}

/// A constant demand on one resource over part of a node's life (GPU §2.3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DemandSegment {
    resource: ResourceId,
    unit: ResourceUnit,
    quantity: u64,
    from: Duration,
    end: SegmentEnd,
}

impl DemandSegment {
    /// `quantity` of `resource` from `from` until `until` after the node starts.
    pub fn transient(
        resource: ResourceId,
        unit: ResourceUnit,
        quantity: u64,
        from: Duration,
        until: Duration,
    ) -> Result<Self, GraphError> {
        if until <= from {
            return Err(GraphError::InvalidDemand {
                reason: "a transient segment must end after it starts",
            });
        }
        Self::checked(
            resource,
            unit,
            quantity,
            from,
            SegmentEnd::AfterStart(until),
        )
    }

    /// `quantity` of `resource` from `from` after the node starts until the request ends.
    pub fn retained(
        resource: ResourceId,
        unit: ResourceUnit,
        quantity: u64,
        from: Duration,
    ) -> Result<Self, GraphError> {
        Self::checked(resource, unit, quantity, from, SegmentEnd::RequestEnd)
    }

    fn checked(
        resource: ResourceId,
        unit: ResourceUnit,
        quantity: u64,
        from: Duration,
        end: SegmentEnd,
    ) -> Result<Self, GraphError> {
        if quantity == 0 {
            return Err(GraphError::InvalidDemand {
                reason: "a segment must demand more than zero",
            });
        }
        Ok(Self {
            resource,
            unit,
            quantity,
            from,
            end,
        })
    }

    /// The resource demanded.
    pub fn resource(&self) -> &ResourceId {
        &self.resource
    }

    /// The unit the quantity is counted in; it must match the declared capacity.
    pub const fn unit(&self) -> ResourceUnit {
        self.unit
    }

    /// The demand, in the resource's unit.
    pub const fn quantity(&self) -> u64 {
        self.quantity
    }

    /// Offset from the node's start.
    pub const fn from(&self) -> Duration {
        self.from
    }

    /// When the demand ends.
    pub const fn end(&self) -> SegmentEnd {
        self.end
    }

    /// Whether the segment lies within a node of this expected duration.
    pub(crate) fn fits_within(&self, expected: Duration) -> bool {
        match self.end {
            SegmentEnd::AfterStart(until) => until <= expected,
            SegmentEnd::RequestEnd => self.from <= expected,
        }
    }
}

/// Resource demand over a node's life as a piecewise-constant profile: the sum of its
/// segments at each instant, so a transient buffer can sit on top of a longer
/// allocation (GPU §2.3).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DemandProfile {
    segments: Vec<DemandSegment>,
}

impl DemandProfile {
    /// A profile made of these segments; overlapping segments add up.
    pub fn new(segments: Vec<DemandSegment>) -> Self {
        Self { segments }
    }

    /// The segments, as given.
    pub fn segments(&self) -> &[DemandSegment] {
        &self.segments
    }

    /// The highest total demand on `resource` at any instant of the node's life.
    pub fn peak(&self, resource: &ResourceId) -> Option<u64> {
        let on: Vec<&DemandSegment> = self
            .segments
            .iter()
            .filter(|segment| &segment.resource == resource)
            .collect();
        on.iter().try_fold(0u64, |peak, probe| {
            let total = on
                .iter()
                .filter(|other| {
                    other.from <= probe.from
                        && match other.end {
                            SegmentEnd::AfterStart(until) => probe.from < until,
                            SegmentEnd::RequestEnd => true,
                        }
                })
                .try_fold(0u64, |sum, other| sum.checked_add(other.quantity))?;
            Some(peak.max(total))
        })
    }
}

/// Where cancellation can stop a node (GPU §2.3, §2.4: batches permit cancellation).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CancellationBoundary {
    /// Only before it starts; once started it runs to completion.
    BeforeStart,
    /// At internal boundaries at most this far apart, such as transport batches.
    Boundaries { max_interval: Duration },
    /// At any instant.
    Anytime,
}

impl CancellationBoundary {
    /// The longest stretch without a cancellation point for a node lasting `duration`.
    pub fn non_preemptible(&self, duration: Duration) -> Duration {
        match self {
            Self::BeforeStart => duration,
            Self::Boundaries { max_interval } => (*max_interval).min(duration),
            Self::Anytime => Duration::ZERO,
        }
    }
}

/// One node of a request graph with everything GPU §2.3 says it carries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeSpec {
    id: NodeId,
    kind: NodeKind,
    identity: Digest,
    trust_scope: TrustScope,
    duration: DurationEstimate,
    completion: CompletionEvent,
    demand: DemandProfile,
    cancellation: CancellationBoundary,
}

impl NodeSpec {
    /// A node with no resource demand that can be cancelled only before it starts; add
    /// demand and cancellation points with [`Self::with_demand`] and
    /// [`Self::with_cancellation`].
    pub fn new(
        id: NodeId,
        kind: NodeKind,
        identity: Digest,
        trust_scope: TrustScope,
        duration: DurationEstimate,
        completion: CompletionEvent,
    ) -> Self {
        Self {
            id,
            kind,
            identity,
            trust_scope,
            duration,
            completion,
            demand: DemandProfile::default(),
            cancellation: CancellationBoundary::BeforeStart,
        }
    }

    /// Replaces the resource demand profile.
    pub fn with_demand(mut self, demand: DemandProfile) -> Self {
        self.demand = demand;
        self
    }

    /// Replaces the cancellation boundary.
    pub fn with_cancellation(mut self, cancellation: CancellationBoundary) -> Self {
        self.cancellation = cancellation;
        self
    }

    /// The node's name in its graph.
    pub fn id(&self) -> &NodeId {
        &self.id
    }

    /// What kind of state or work the node is.
    pub const fn kind(&self) -> NodeKind {
        self.kind
    }

    /// The semantic/compatibility identity of the state this node establishes (§2.3).
    pub const fn identity(&self) -> &Digest {
        &self.identity
    }

    /// The trust scope the node produces state in and consumes state into.
    pub fn trust_scope(&self) -> &TrustScope {
        &self.trust_scope
    }

    /// The duration estimate and its uncertainty interval.
    pub const fn duration(&self) -> &DurationEstimate {
        &self.duration
    }

    /// The event that establishes usability; the node finishes when it happens.
    pub const fn completion(&self) -> CompletionEvent {
        self.completion
    }

    /// Resource demand over the node's life.
    pub fn demand(&self) -> &DemandProfile {
        &self.demand
    }

    /// Where cancellation can stop the node.
    pub const fn cancellation(&self) -> CancellationBoundary {
        self.cancellation
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ms(value: u64) -> Duration {
        Duration::from_millis(value)
    }

    fn vram() -> ResourceId {
        ResourceId::new("gpu0.vram").unwrap()
    }

    #[test]
    fn duration_interval_must_hold_expected() {
        let estimate = DurationEstimate::new(ms(8), ms(10), ms(15)).unwrap();
        assert_eq!(
            (estimate.low(), estimate.expected(), estimate.high()),
            (ms(8), ms(10), ms(15))
        );
        assert!(DurationEstimate::new(ms(11), ms(10), ms(15)).is_err());
        assert!(DurationEstimate::new(ms(8), ms(10), ms(9)).is_err());
        assert!(DurationEstimate::exact(Duration::ZERO).is_err());
        assert_eq!(DurationEstimate::exact(ms(3)).unwrap().high(), ms(3));
    }

    #[test]
    fn every_kind_has_exactly_the_events_that_establish_usability() {
        let usable: Vec<(NodeKind, usize)> = NodeKind::ALL
            .iter()
            .map(|kind| {
                let count = [
                    CompletionEvent::ExtentVerified,
                    CompletionEvent::EngineReady,
                    CompletionEvent::LayoutPublished,
                    CompletionEvent::AdapterActivated,
                    CompletionEvent::TokenizerLoaded,
                    CompletionEvent::KvBlockPublished,
                    CompletionEvent::GraphKeyValidated,
                    CompletionEvent::CommunicatorReady,
                    CompletionEvent::ComputeCompleted,
                    CompletionEvent::FirstTokenDelivered,
                    CompletionEvent::ResponseDelivered,
                ]
                .into_iter()
                .filter(|event| kind.accepts(*event))
                .count();
                (*kind, count)
            })
            .collect();
        for (kind, count) in usable {
            let expected = if kind == NodeKind::NetworkResponse {
                2
            } else {
                1
            };
            assert_eq!(count, expected, "{kind:?}");
        }
        assert!(!NodeKind::ArtifactExtent.accepts(CompletionEvent::ComputeCompleted));
        assert!(!NodeKind::Compute.can_be_ready());
        assert!(!NodeKind::NetworkResponse.can_be_ready());
        assert!(NodeKind::KvBlock.can_be_ready());
    }

    #[test]
    fn segments_refuse_empty_demand() {
        assert!(DemandSegment::transient(vram(), ResourceUnit::Bytes, 1, ms(5), ms(5)).is_err());
        assert!(DemandSegment::transient(vram(), ResourceUnit::Bytes, 0, ms(0), ms(5)).is_err());
        assert!(DemandSegment::retained(vram(), ResourceUnit::Bytes, 0, ms(0)).is_err());
        let segment =
            DemandSegment::transient(vram(), ResourceUnit::Bytes, 4, ms(1), ms(5)).unwrap();
        assert!(segment.fits_within(ms(5)));
        assert!(!segment.fits_within(ms(4)));
        let held = DemandSegment::retained(vram(), ResourceUnit::Bytes, 4, ms(5)).unwrap();
        assert!(held.fits_within(ms(5)));
        assert!(!held.fits_within(ms(4)));
    }

    #[test]
    fn profile_peak_adds_a_transient_buffer_to_a_held_allocation() {
        let profile = DemandProfile::new(vec![
            DemandSegment::retained(vram(), ResourceUnit::Bytes, 100, ms(0)).unwrap(),
            DemandSegment::transient(vram(), ResourceUnit::Bytes, 30, ms(2), ms(6)).unwrap(),
            DemandSegment::transient(vram(), ResourceUnit::Bytes, 50, ms(6), ms(8)).unwrap(),
        ]);
        assert_eq!(profile.peak(&vram()), Some(150));
        assert_eq!(profile.peak(&ResourceId::new("pcie").unwrap()), Some(0));
    }

    #[test]
    fn cancellation_boundaries_bound_the_non_preemptible_stretch() {
        assert_eq!(
            CancellationBoundary::BeforeStart.non_preemptible(ms(40)),
            ms(40)
        );
        let batches = CancellationBoundary::Boundaries {
            max_interval: ms(4),
        };
        assert_eq!(batches.non_preemptible(ms(40)), ms(4));
        assert_eq!(batches.non_preemptible(ms(3)), ms(3));
        assert_eq!(
            CancellationBoundary::Anytime.non_preemptible(ms(40)),
            Duration::ZERO
        );
    }
}
